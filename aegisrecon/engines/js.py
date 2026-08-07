"""JavaScript harvesting engine.

Discovers and downloads JavaScript files from in-scope assets using
ProjectDiscovery katana for crawling, then fetches file bodies so they can be
content-hashed, stored, and scanned for secrets.

The step is scope-gated: katana is only ever pointed at already-authorized
program assets.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from aegisrecon.core.database import Database
from aegisrecon.core.models import Asset, AssetFile
from aegisrecon.core.repositories import AssetFileRepository, AssetRepository
from aegisrecon.exceptions import ToolNotFoundError, tool_not_found_message
from aegisrecon.utils.retry import retry

logger = logging.getLogger("aegisrecon.engines.js")

JS_SUFFIXES = (".js", ".mjs", ".cjs")


@dataclass(frozen=True)
class HarvestedFile:
    """A downloaded JavaScript file."""

    url: str
    content: str
    hash: str
    size: int


@dataclass
class HarvestResult:
    """Statistics for a JS harvest pass."""

    program_id: str
    candidates: int = 0
    fetched: int = 0
    new_files: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)


class KatanaCrawler:
    """Wraps ProjectDiscovery katana to enumerate JS URLs."""

    def __init__(self, binary: str = "katana") -> None:
        resolved = shutil.which(binary)
        if resolved is None:
            raise ToolNotFoundError(
                tool_not_found_message(
                    binary, "AEGISRECON_KATANA_BIN", "github.com/projectdiscovery/katana"
                )
            )
        self.binary_path = resolved

    @retry(attempts=2, logger_=logger, exceptions=(subprocess.CalledProcessError,))
    def crawl_js(self, targets: list[str]) -> list[str]:
        """Return candidate JS file URLs discovered under *targets*."""
        jsl = ["-js-crawl", "-silent", "-jsl"]
        command = [self.binary_path, "-u", ",".join(targets), *jsl]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, stderr=proc.stderr)
        return [urljoin(line.strip(), "") for line in proc.stdout.splitlines() if line.strip()]


class JsHarvestEngine:
    """Discovers, downloads and stores JavaScript files for in-scope assets."""

    def __init__(self, database: Database, binary: str = "katana", timeout: float = 20.0) -> None:
        self.database = database
        self.crawler = KatanaCrawler(binary=binary)
        self.timeout = timeout

    def run(self, program_id: str, hostnames: list[str] | None = None) -> HarvestResult:
        """Harvest JS from a program's in-scope assets (or explicit hosts)."""
        if hostnames is None:
            with self.database.session() as session:
                hostnames = AssetRepository(session).list_names(program_id)
                session.close()

        result = HarvestResult(program_id=program_id)
        if not hostnames:
            return result

        targets = [host if host.startswith("http") else f"https://{host}" for host in hostnames]
        urls = self.crawler.crawl_js(targets)
        result.candidates = len(urls)
        urls = [u for u in urls if u.endswith(JS_SUFFIXES)]

        remote_files = self._download(urls)
        result.fetched = len(remote_files)
        self._persist(program_id, remote_files, result)
        return result

    def _download(self, urls: list[str]) -> list[HarvestedFile]:
        """Download JS bodies with bounded parallelism."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        fetched: list[HarvestedFile] = []
        with httpx.Client(timeout=httpx.Timeout(self.timeout), follow_redirects=True) as client:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(_fetch, client, url, self.timeout): url for url in urls}
                for future in as_completed(futures):
                    try:
                        item = future.result()
                        if item is not None:
                            fetched.append(item)
                    except Exception as exc:  # noqa: BLE001 - isolate per-URL failures
                        logger.debug("download failed for %s: %s", futures[future], exc)
        return fetched

    def _persist(self, program_id: str, files: list[HarvestedFile], result: HarvestResult) -> None:
        with self.database.session() as session:
            assets = AssetRepository(session)
            repo = AssetFileRepository(session)

            for file in files:
                asset = self._find_asset(assets, program_id, file.url)
                if asset is None:
                    result.errors.append(file.url)
                    continue
                existing = repo.get_by_url(asset.id, file.url)
                if existing is not None:
                    if existing.hash == file.hash:
                        result.unchanged += 1
                        continue
                    repo.update(existing.id, content=file.content, hash=file.hash, size=file.size)
                    result.new_files += 1
                    continue
                repo.create(
                    AssetFile(
                        asset_id=asset.id,
                        url=file.url,
                        kind="javascript",
                        hash=file.hash,
                        size=file.size,
                        content=file.content,
                    )
                )
                result.new_files += 1

            session.commit()

    @staticmethod
    def _find_asset(assets: AssetRepository, program_id: str, url: str) -> Asset | None:
        from urllib.parse import urlparse

        try:
            host = urlparse(url).netloc.split(":")[0].lower()
        except ValueError:
            return None
        if not host:
            return None
        return assets.get_by_name(program_id, host)


def _fetch(client: httpx.Client, url: str, timeout: float) -> HarvestedFile | None:
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPError:
        return None
    if not response.url.path.endswith(JS_SUFFIXES):
        return None
    content = response.text
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return HarvestedFile(url=str(response.url), content=content, hash=digest, size=len(content))


__all__ = ["JsHarvestEngine", "HarvestResult", "KatanaCrawler"]
