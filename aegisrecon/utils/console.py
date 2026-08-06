"""Console helpers built on top of Rich.

Centralizing the Rich console prevents accidental output to stdout that would
corrupt piped machine-readable output (JSON, CSV). All interactive/status
output goes through :data:`console`, which writes to stderr.
"""

from __future__ import annotations

from rich.console import Console

console = Console(stderr=True, soft_wrap=True)

__all__ = ["console"]
