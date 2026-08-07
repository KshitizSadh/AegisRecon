"""Screenshot capture engine.

Captures visual renders of a program's live endpoints using ProjectDiscovery
``httpx -screenshot``, then stores each render on disk and records a
:class:`~aegisrecon.core.models.AssetFile` entry (kind ``screenshot``) so
screenshots join the same forensics pipeline as other harvested files.

As with every active step, only already-authorized, stored endpoints are handed
to httpx.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from aegisrecon.core.database import Database
from aegisrecon.core.models import AssetFile
from aegisrecon.core.repositories import AssetFileRepository, EndpointRepository
from aegisrecon.exceptions import ToolNotFoundError, tool_not_found_message

logger = logging.getLogger("aegisrecon.engines.screenshot")

RENDER_SUFFIXES = (".png", ".jpg", ".jpeg")


@dataclass
class ScreenshotResult:
    """Statistics for a screenshot pass."""

    program_id: str
    endpoints_attempted: int = 0
    new_files: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


class ScreenshotEngine:
    """Captures and stores screenshots for a program's endpoints."""

    def __init__(
        self,
        database: Database,
        binary: str = "httpx",
        output_root: Path | None = None,
        timeout: float = 30.0,
        cwd: Path | None = None,
    ) -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                tool_not_found_message(
                    binary or "httpx", "AEGISRECON_HTTPX_BIN", "github.com/projectdiscovery/httpx"
                )
            )
        self.database = database
        self.binary_path = resolved
        self.output_root = output_root or Path("screenshots")
        self.timeout = timeout
        self.cwd = cwd

    def run(self, program_id: str) -> ScreenshotResult:
        """Capture screenshots for a program's live endpoints."""
        result = ScreenshotResult(program_id=program_id)

        with self.database.session() as session:
            endpoints = EndpointRepository(session).list_for_program(program_id)
            session.close()

        program_dir = self.output_root / program_id
        program_dir.mkdir(parents=True, exist_ok=True)

        for index, endpoint in enumerate(endpoints):
            result.endpoints_attempted += 1
            store = program_dir / ".tmp" / str(index)
            store.mkdir(parents=True, exist_ok=True)
            try:
                self._invoke_httpx(endpoint.url, store)
                renders = self._find_renders(store)
            except Exception as exc:  # noqa: BLE001 - isolate per-endpoint failures
                result.errors.append(endpoint.url)
                logger.warning("screenshot failed for %s: %s", endpoint.url, exc)
                renders = []

            assets_dir = program_dir / _host_of(endpoint.url)
            assets_dir.mkdir(parents=True, exist_ok=True)
            committed = self._persist(endpoint.asset_id, endpoint.url, renders, assets_dir, result)
            logger.debug("committed %d screenshots for %s", committed, endpoint.url)
            shutil.rmtree(store, ignore_errors=True)

        shutil.rmtree(program_dir / ".tmp", ignore_errors=True)
        logger.info("screenshot: %d new files for %s", result.new_files, program_id)
        return result

    def _invoke_httpx(self, url: str, store: Path) -> None:
        command = [
            self.binary_path,
            "-silent",
            "-screenshot",
            "-store-response-dir",
            str(store),
            "-u",
            url,
            "-timeout",
            str(int(self.timeout)),
        ]
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.timeout + 5,
            check=False,
            cwd=self.cwd,
        )
        if proc.returncode != 0:
            logger.debug("httpx screenshot returned %d for %s", proc.returncode, url)

    @staticmethod
    def _find_renders(store: Path) -> list[Path]:
        if not store.exists():
            return []
        return [p for p in store.rglob("*") if p.is_file() and p.suffix.lower() in RENDER_SUFFIXES]

    def _persist(
        self,
        asset_id: str,
        url: str,
        renders: list[Path],
        assets_dir: Path,
        result: ScreenshotResult,
    ) -> int:
        committed = 0
        if not renders:
            return 0
        with self.database.session() as session:
            files = AssetFileRepository(session)
            for i, render in enumerate(renders):
                dest = assets_dir / f"{i}_{render.name}"
                shutil.move(str(render), str(dest))
                digest = hashlib.sha256(dest.read_bytes()).hexdigest()
                if files.get_by_path(asset_id, str(dest)):
                    result.skipped += 1
                    continue
                files.create(
                    AssetFile(
                        asset_id=asset_id,
                        url=url,
                        kind="screenshot",
                        hash=digest,
                        size=dest.stat().st_size,
                        content="",
                        path=str(dest),
                    )
                )
                result.new_files += 1
                committed += 1
            session.commit()
        return committed


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    host = urlparse(url).netloc.split(":")[0]
    return host or "unknown"


__all__ = ["ScreenshotEngine", "ScreenshotResult"]
