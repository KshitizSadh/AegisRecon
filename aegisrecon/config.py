"""Runtime configuration for AegisRecon.

Configuration is layered: sensible defaults -> environment variables ->
explicit CLI flags / a config file. Values can be overridden through
``AEGISRECON_*`` environment variables (see :class:`AegisSettings`).

All persisted state lives inside a single *data directory* so that an
engagement can be archived or shared by copying one folder.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from aegisrecon.exceptions import ConfigError


def default_data_dir() -> Path:
    """Return the default location for AegisRecon state.

    Uses ``AEGISRECON_DATA_DIR`` if set, otherwise ``~/.aegisrecon``.
    """
    env = os.environ.get("AEGISRECON_DATA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".aegisrecon"


class AegisSettings(BaseSettings):
    """Typed, environment-aware configuration for the framework."""

    model_config = SettingsConfigDict(
        env_prefix="AEGISRECON_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Storage -------------------------------------------------------
    data_dir: Path = Field(
        default_factory=default_data_dir, description="Root directory for all state"
    )
    db_path: Path | None = Field(
        default=None, description="Explicit SQLite database path (overrides data_dir)"
    )
    state_file: str = Field(default="state.json", description="File name for framework state JSON")

    # --- Networking / engines ------------------------------------------
    concurrency: int = Field(default=20, ge=1, le=200, description="Default parallel worker count")
    timeout_seconds: float = Field(
        default=10.0, gt=0, le=300, description="Per-request timeout in seconds"
    )
    retries: int = Field(
        default=2, ge=0, le=10, description="Number of retries for transient failures"
    )
    dns_concurrency: int = Field(
        default=50, ge=1, le=500, description="Parallel DNS resolution workers"
    )

    # --- External tooling ------------------------------------------------
    httpx_bin: str = Field(
        default="httpx", description="Path or name of the ProjectDiscovery httpx binary"
    )
    subfinder_bin: str = Field(
        default="subfinder", description="Path or name of the ProjectDiscovery subfinder binary"
    )
    naabu_bin: str = Field(
        default="naabu", description="Path or name of the ProjectDiscovery naabu binary"
    )
    katana_bin: str = Field(
        default="katana", description="Path or name of the ProjectDiscovery katana binary"
    )
    use_external_httpx: bool = Field(
        default=True,
        description="Shell out to ProjectDiscovery httpx for HTTP probing",
    )
    auto_install_tools: bool = Field(
        default=False,
        description="Attempt to install missing ProjectDiscovery binaries (requires Go)",
    )

    # --- Passive sources --------------------------------------------------
    enable_ct_logs: bool = Field(
        default=True, description="Enable Certificate Transparency passive discovery"
    )
    enable_dns_records: bool = Field(
        default=True, description="Enable passive DNS record collection"
    )
    ct_logs_timeout: float = Field(
        default=20.0, gt=0, le=120, description="CT log query timeout in seconds"
    )

    # --- Privacy / safety ---------------------------------------------------
    require_scope: bool = Field(
        default=True,
        description="Block all discovery outside explicitly authorized program scope",
    )
    verbose: bool = Field(default=False, description="Enable verbose logging")
    debug: bool = Field(default=False, description="Enable debug-level logging (never log secrets)")

    # --- Reporting -----------------------------------------------------------
    report_dir: str = Field(
        default="reports", description="Directory for generated reports (relative to data_dir)"
    )
    screenshot_dir: str = Field(
        default="screenshots",
        description="Directory for captured screenshots (relative to data_dir)",
    )

    # --- Derived helpers ----------------------------------------------------
    @property
    def database_path(self) -> Path:
        """Resolve the effective SQLite database path."""
        if self.db_path is not None:
            return self.db_path.expanduser().resolve()
        return (self.data_dir / "aegisrecon.db").resolve()

    @property
    def reports_path(self) -> Path:
        """Resolve the reports output directory."""
        return self.data_dir / self.report_dir

    @property
    def screenshots_path(self) -> Path:
        """Resolve the screenshots output directory."""
        return self.data_dir / self.screenshot_dir

    @field_validator("data_dir")
    @classmethod
    def _expand_data_dir(cls, value: Path) -> Path:
        return Path(value).expanduser()

    @field_validator("state_file")
    @classmethod
    def _validate_state_file(cls, value: str) -> str:
        if not value.endswith(".json"):
            raise ValueError("state_file must end in .json")
        return value

    def prepare(self) -> None:
        """Create the data directory structure.

        Raises :class:`ConfigError` if the directory cannot be created (for
        example when a file occupies the path).
        """
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.reports_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:  # pragma: no cover - environment dependent
            raise ConfigError(f"cannot create data directory {self.data_dir}: {exc}") from exc

    def require_tool(self, name: str) -> str:
        """Resolve the path of an external binary or raise :class:`ConfigError`."""
        binary = getattr(self, f"{name}_bin", name)
        resolved = shutil.which(binary)
        if resolved is None:
            hint = (
                f"Install it from https://github.com/projectdiscovery/{name}/releases "
                "or set AEGISRECON_*_BIN to its location."
            )
            raise ConfigError(f"external tool '{binary}' was not found on PATH. {hint}")
        return resolved


__all__ = ["AegisSettings", "default_data_dir"]
