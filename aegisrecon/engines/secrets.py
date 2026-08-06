"""Secret detection engine.

Detects likely credentials and sensitive values in text (JavaScript files,
configuration responses, etc.) using a combination of regular expressions and
Shannon entropy. All detection is heuristic: a positive match is a candidate
that a researcher must verify; nothing here claims a secret is valid.

The engine is pure and side-effect free so it can be unit tested exhaustively.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# (name, regex, min_entropy). Rules with group(2) extract the value; others
# use the full match. `private_key_block` and `slack_webhook` match the whole
# pattern (blocks/URLs, not a single token).
_RULES: tuple[tuple[str, str, float], ...] = (
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}", 3.0),
    (
        "aws_secret_access_key",
        r"""(?i)\b(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})""",
        3.5,
    ),
    ("github_token", r"(?i)\bgh[pousr]_[A-Za-z0-9_]{30,255}", 3.5),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", 3.0),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,250}", 3.0),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+", 3.0),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.0),
    ("google_oauth_id", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", 2.5),
    ("twilio_api_key", r"\bSK[0-9a-fA-F]{32}", 3.0),
    ("stripe_live_key", r"(?i)\bstripe\s*live[_ -]?(?:sk|pk|rk)_[A-Za-z0-9]{16,}", 3.0),
    ("jwt_token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", 3.0),
    ("mailgun_api_key", r"\bkey-[0-9a-zA-Z]{32}", 2.5),
    (
        "generic_secret_assignment",
        r"""(?i)\b(?:api[_-]?key|apikey|secret|token|password|passwd|client_secret|access_token|auth)\b[^=\n]{0,40}=\s*['"]?([^\s'"]{12,})""",
        4.5,
    ),
)

# Common non-secret placeholder values that would otherwise match.
_BLOCKLIST = {
    "example",
    "your-api-key-here",
    "your-secret-here",
    "your_token_here",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "changeme",
    "todo",
    "test",
    "demo",
    "loremipsum",
    "none",
    "null",
}


@dataclass(frozen=True)
class SecretCandidate:
    """A single detected candidate."""

    kind: str
    value: str
    context: str
    entropy: float


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of *value*."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def scan(content: str, min_entropy: float = 0.0) -> list[SecretCandidate]:
    """Scan *content* and return detected secret candidates.

    Args:
        content: The text to scan (e.g. a JavaScript file body).
        min_entropy: Only report candidates with at least this entropy
            (0 disables the extra threshold on top of per-rule thresholds).
    """
    if not content:
        return []
    found: dict[tuple[str, str], SecretCandidate] = {}

    for name, pattern, rule_entropy in _RULES:
        for match in re.finditer(pattern, content, flags=re.MULTILINE):
            value = _extract_value(match, name)
            if not value or value.lower() in _BLOCKLIST:
                continue
            entropy = shannon_entropy(value)
            if entropy < rule_entropy:
                continue
            if min_entropy and entropy < min_entropy:
                continue
            window = _context_snippet(content, match.start())
            found[(name, value)] = SecretCandidate(
                kind=name,
                value=value,
                context=window,
                entropy=round(entropy, 3),
            )

    return list(found.values())


def _extract_value(match: re.Match, name: str) -> str:
    """Extract the candidate value from a regex match."""
    if name == "private_key_block":
        return match.group(0) or ""
    if match.lastindex:
        value = match.group(match.lastindex) or ""
    else:
        value = match.group(0) or ""
    return value.strip().strip("\"'`").rstrip(",").strip()


def _context_snippet(content: str, index: int, radius: int = 60) -> str:
    start = max(0, index - radius)
    end = min(len(content), index + 120)
    return content[start:end].replace("\n", " ").strip()


__all__ = ["SecretCandidate", "scan", "shannon_entropy"]
