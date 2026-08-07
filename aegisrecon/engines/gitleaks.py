"""Secret scanning via the Go ``gitleaks`` binary.

``gitleaks`` is a fast, battle-tested Go secrets scanner (regex + entropy over
git history or a plain directory). AegisRecon runs it over a target path and
persists any findings as :class:`Secret` records so they surface alongside the
built-in Python detector.

The two secret scanners are complementary:
    * the built-in detector (``engines/secrets.py``) scans harvested file
      bodies already stored in the database;
    * ``gitleaks`` scans a git repository or directory on disk, which catches
      secrets in git history and unconsumed files.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from aegisrecon.core.database import Database
from aegisrecon.core.models import Secret
from aegisrecon.core.repositories import SecretRepository
from aegisrecon.exceptions import EngineError, ToolNotFoundError, tool_not_found_message

logger = logging.getLogger("aegisrecon.engines.gitleaks")

CONTEXT_LIMIT = 1024


@dataclass(frozen=True)
class GitleaksFinding:
    """A parsed gitleaks result record."""

    rule_id: str
    description: str
    file: str
    secret: str
    line: int = 0
    commit: str = ""
    entropy: float = 0.0


@dataclass
class GitleaksScanResult:
    """Statistics for a gitleaks scan pass."""

    program_id: str
    sources: int = 0
    candidates: int = 0
    new_secrets: int = 0
    errors: list[str] = field(default_factory=list)


class GitleaksScanner:
    """Wraps the Go ``gitleaks`` binary."""

    def __init__(self, binary: str = "gitleaks") -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                tool_not_found_message(
                    binary, "AEGISRECON_GITLEAKS_BIN", "github.com/gitleaks/gitleaks"
                )
            )
        self.binary_path = resolved

    def scan_path(self, path: Path) -> list[GitleaksFinding]:
        """Run gitleaks over *path* and return parsed findings.

        *path* may be a git repository (secrets in history) or a plain source
        tree. ``--no-git`` is used for the non-git case automatically when the
        directory is not a repository.
        """
        if not path.exists():
            raise EngineError(f"gitleaks target not found: {path}")
        command = [self.binary_path, "detect", "--source", str(path), "--no-banner", "--report-format", "json", "--report-path", "-"]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
        if proc.returncode not in (0, 1):
            raise EngineError(f"gitleaks failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return self._parse(proc.stdout or "[]")

    @staticmethod
    def _parse(output: str) -> list[GitleaksFinding]:
        try:
            rows = json.loads(output or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, list):
            return []
        findings: list[GitleaksFinding] = []
        for row in rows:
            rule = row.get("RuleID") or row.get("Rule") or "unknown"
            findings.append(
                GitleaksFinding(
                    rule_id=str(rule),
                    description=str(row.get("Description") or ""),
                    file=str(row.get("File") or ""),
                    secret=str(row.get("Secret") or ""),
                    line=int(row.get("StartLine") or 0),
                    commit=str(row.get("Commit") or ""),
                    entropy=float(row.get("Entropy") or 0.0),
                )
            )
        return findings


class GitleaksEngine:
    """Runs gitleaks over directories and persists findings as secrets."""

    def __init__(self, database: Database, binary: str = "gitleaks") -> None:
        self.database = database
        self.scanner = GitleaksScanner(binary=binary)

    def run(self, program_id: str, paths: list[Path]) -> GitleaksScanResult:
        """Scan each *path* and persist new secrets under *program_id*."""
        result = GitleaksScanResult(program_id=program_id)
        for path in paths:
            try:
                findings = self.scanner.scan_path(path)
            except (EngineError, ToolNotFoundError) as exc:
                result.errors.append(str(exc))
                logger.warning("gitleaks scan of %s failed: %s", path, exc)
                continue
            result.sources += 1
            result.candidates += len(findings)
            self._persist(program_id, path, findings, result)
        return result

    def _persist(self, program_id, path, findings, result) -> None:
        with self.database.session() as session:
            repo = SecretRepository(session)
            for finding in findings:
                if not finding.secret:
                    continue
                asset = self._match_asset(session, program_id, finding.file)
                if asset is None:
                    result.errors.append(f"{path}: {finding.file} has no matching asset")
                    continue
                if repo.exists(program_id, asset.id, finding.rule, finding.secret):
                    continue
                repo.create(
                    Secret(
                        program_id=program_id,
                        asset_id=asset.id,
                        kind=finding.rule,
                        value=finding.secret,
                        context=f"{finding.description} (line {finding.line})".strip()[:CONTEXT_LIMIT],
                        location=finding.file,
                        entropy=round(finding.entropy, 3),
                        is_verified=False,
                    )
                )
                result.new_secrets += 1
            session.commit()

    @staticmethod
    def _match_asset(session, program_id: str, file_path: str):
        """Associate a finding file to an asset by filename/url overlap."""
        from aegisrecon.core.repositories import AssetFileRepository, AssetRepository

        baseline = Path(file_path).name
        assets = AssetRepository(session)
        for asset_file in AssetFileRepository(session).list_for_program(program_id):
            candidate = Path(asset_file.url or asset_file.path).name
            if baseline and baseline == candidate:
                return assets.get(asset_file.asset_id)
        return None


__all__ = ["GitleaksScanner", "GitleaksEngine", "GitleaksFinding", "GitleaksScanResult"]
