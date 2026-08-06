"""Secret scanning engine.

Runs the :mod:`aegisrecon.engines.secrets` detector over harvested asset files,
then persists detected candidates as :class:`~aegisrecon.core.models.Secret`
records under the owning program.

Persisted secrets are conservative: one record per (asset, kind, value) and
nothing is ever marked verified.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from aegisrecon.core.database import Database
from aegisrecon.core.models import Secret
from aegisrecon.core.repositories import AssetFileRepository, SecretRepository
from aegisrecon.engines.secrets import scan as scan_content

logger = logging.getLogger("aegisrecon.engines.secretscan")

# Cap context snippets stored in the database.
CONTEXT_LIMIT = 1024


@dataclass
class SecretScanResult:
    """Statistics for a secret scan pass."""

    program_id: str
    files_checked: int = 0
    candidates: int = 0
    new_secrets: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)


class SecretEngine:
    """Detects and persists sensitive values across a program's content."""

    def __init__(self, database: Database, min_entropy: float = 0.0) -> None:
        self.database = database
        self.min_entropy = min_entropy

    def run(self, program_id: str) -> SecretScanResult:
        """Scan all harvested asset files for secrets."""
        result = SecretScanResult(program_id=program_id)

        with self.database.session() as session:
            secrets = SecretRepository(session)
            files = AssetFileRepository(session)

            for asset_file in files.list_for_program(program_id):
                if not asset_file.content:
                    continue
                result.files_checked += 1
                self._scan_text(
                    program_id=program_id,
                    asset_id=asset_file.asset_id,
                    location=asset_file.url,
                    content=asset_file.content,
                    secrets=secrets,
                    result=result,
                )

            session.commit()

        logger.info(
            "secret scan: %d candidates (%d new) across %d files",
            result.candidates,
            result.new_secrets,
            result.files_checked,
        )
        return result

    def _scan_text(self, program_id, asset_id, location, content, secrets, result) -> None:
        for candidate in scan_content(content, min_entropy=self.min_entropy):
            result.candidates += 1
            result.by_kind[candidate.kind] = result.by_kind.get(candidate.kind, 0) + 1
            if secrets.exists(program_id, asset_id, candidate.kind, candidate.value):
                continue
            secrets.create(
                Secret(
                    program_id=program_id,
                    asset_id=asset_id,
                    kind=candidate.kind,
                    value=candidate.value,
                    context=candidate.context[:CONTEXT_LIMIT],
                    location=location or "",
                    entropy=candidate.entropy,
                    is_verified=False,
                )
            )
            result.new_secrets += 1


__all__ = ["SecretEngine", "SecretScanResult"]
