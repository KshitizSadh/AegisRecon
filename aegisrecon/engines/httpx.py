"""HTTP probing via ProjectDiscovery httpx.

``httpx`` (projectdiscovery/httpx) is the industry standard fast HTTP prober.
AegisRecon shells out to it, parses its JSONL output, and ingests the results
into the asset database. The engine supports the same concurrency/retry
semantics as the rest of the framework.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegisrecon.exceptions import ToolNotFoundError
from aegisrecon.utils.retry import retry

logger = logging.getLogger("aegisrecon.engines.httpx")

JSONL_FLAGS = (
    "-json",
    "-silent",
    "-nc",
    "-retries",
    "2",
    "-threads",
    "50",
    "-timeout",
    "8",
    "-title",
    "-tech-detect",
    "-status-code",
    "-content-type",
    "-web-server",
    "-follow-redirects",
    "-max-redirects",
    "5",
)


@dataclass(frozen=True)
class ProbingResult:
    """A parsed JSONL record produced by httpx."""

    url: str
    status_code: int | None
    title: str
    content_type: str
    web_server: str
    technologies: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict)


class HttpxProber:
    """Wraps the ProjectDiscovery httpx binary."""

    def __init__(self, binary: str = "httpx") -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                f"httpx binary {binary!r} was not found on PATH. "
                "Install it from https://github.com/projectdiscovery/httpx/releases "
                "or set AEGISRECON_HTTPX_BIN."
            )
        self.binary_path = resolved
        logger.debug("using httpx at %s", self.binary_path)

    def probe(
        self, targets: Iterable[str], extra_flags: list[str] | None = None
    ) -> list[ProbingResult]:
        """Run httpx against *targets* and return parsed results.

        Raises:
            EngineError: When the httpx process exits abnormally.
        """
        lines = list(targets)
        if not lines:
            return []

        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("\n".join(lines))
            target_file = Path(handle.name)

        try:
            output = self._run(target_file, extra_flags)
        finally:
            target_file.unlink(missing_ok=True)

        return [self._parse(line) for line in output.splitlines() if line.strip()]

    @retry(attempts=2, logger_=logger, exceptions=(subprocess.CalledProcessError,))
    def _run(self, target_file: Path, extra_flags: list[str] | None) -> str:
        command = [self.binary_path, "-l", str(target_file), *JSONL_FLAGS, *(extra_flags or [])]
        logger.debug("running: %s", " ".join(command))
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, stderr=proc.stderr)
        return proc.stdout or ""

    @staticmethod
    def _parse(line: str) -> ProbingResult:
        try:
            payload: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("skipping unparseable httpx line: %s", line[:200])
            return ProbingResult(
                url=line.strip(),
                status_code=None,
                title="",
                content_type="",
                web_server="",
                technologies=(),
            )

        tech = payload.get("tech", []) or []
        return ProbingResult(
            url=payload.get("url") or "",
            status_code=payload.get("status_code"),
            title=payload.get("title") or "",
            content_type=payload.get("content_type") or "",
            web_server=payload.get("webserver") or "",
            technologies=tuple(sorted({str(t) for t in tech})),
            raw=payload,
        )


__all__ = ["HttpxProber", "ProbingResult"]
