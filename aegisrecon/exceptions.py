"""Package-level exceptions for AegisRecon.

A small, explicit exception hierarchy lets higher layers (the CLI, the engine,
or callers) catch distinct failure modes without string matching. All
framework-specific exceptions derive from :class:`AegisReconError`.
"""

from __future__ import annotations


class AegisReconError(Exception):
    """Base class for all AegisRecon-specific errors."""


class ConfigError(AegisReconError):
    """Raised when configuration is invalid or cannot be loaded."""


class ValidationError(AegisReconError):
    """Raised when an object fails domain validation."""


class ScopeValidationError(ValidationError):
    """Raised when a target is outside the authorized program scope."""


class DatabaseError(AegisReconError):
    """Raised when a database operation fails."""


class StorageError(AegisReconError):
    """Raised when the SQLite store cannot be initialised or accessed."""


class EntityNotFoundError(DatabaseError):
    """Raised when a requested entity does not exist in the store."""


class EngineError(AegisReconError):
    """Base class for recon/scanner engine failures."""


class ToolNotFoundError(EngineError):
    """Raised when an external binary required by an engine is missing."""


def tool_not_found_message(binary: str, env_key: str, project_url: str) -> str:
    """Compose the standard "binary is missing" hint used across engines."""
    return (
        f"external binary {binary!r} was not found on PATH. "
        f"Install it with `aegisrecon tools install {binary}` via Go "
        f"({project_url}) or set {env_key} to its location."
    )


class ReconError(EngineError):
    """Raised when a recon discovery step fails irrecoverably."""


class ResolutionError(ReconError):
    """Raised when hostname resolution fails."""


class ReportError(AegisReconError):
    """Raised when a report cannot be generated or written."""
