"""Scope validation — the safety gate of AegisRecon.

Every asset that the recon engine considers is passed through
:class:`ScopeValidator` before being stored or scanned. If a target is not
explicitly authorized, it is rejected. This is the enforcement point that
keeps AegisRecon within authorized bug bounty programs.

Matching semantics:
    * **exact** — matches a single hostname byte-for-byte.
    * **wildcard** — ``*.example.com`` matches ``example.com`` and any depth of
      subdomain under it.
    * **regex** — a compiled pattern matched against the full hostname.

Priority (deny-first):
    1. If an **exclude** rule matches, the target is out of scope.
    2. If an **include** rule matches, the target is in scope.
    3. With no matching include rule, the target is out of scope (deny by default).
"""

from __future__ import annotations

import fnmatch
import re
from typing import Iterator

from aegisrecon.core.models import ScopeAction, ScopeEntry, ScopeKind
from aegisrecon.utils.validators import normalize_hostname


class ScopeRule:
    """A compiled, fast-to-match scope rule."""

    __slots__ = ("entry", "_compiled")

    def __init__(self, entry: ScopeEntry) -> None:
        self.entry = entry
        self._compiled = _compile(entry)

    @property
    def action(self) -> ScopeAction:
        return self.entry.action

    def matches(self, hostname: str) -> bool:
        """Return True when this rule matches the (normalized) hostname."""
        target = normalize_hostname(hostname)
        return bool(self._compiled(target))


def _compile(entry: ScopeEntry):
    """Return a matcher callable for a scope entry."""
    value = normalize_hostname(entry.value)
    if entry.kind == ScopeKind.WILDCARD:
        pattern = value
        if pattern.startswith("*."):
            pattern = pattern[2:]
        return lambda target: target == pattern or fnmatch.fnmatch(target, f"*.{pattern}")
    if entry.kind == ScopeKind.REGEX:
        try:
            compiled = re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid scope regex {value!r}: {exc}") from exc
        return lambda target: compiled.fullmatch(target) is not None
    return lambda target: target == value


class ScopeValidator:
    """Determines whether hostnames fall inside an authorized program scope."""

    def __init__(self, entries: list[ScopeEntry]) -> None:
        self.include_rules: list[ScopeRule] = []
        self.exclude_rules: list[ScopeRule] = []
        for entry in entries:
            rule = ScopeRule(entry)
            if rule.action == ScopeAction.EXCLUDE:
                self.exclude_rules.append(rule)
            else:
                self.include_rules.append(rule)

    @property
    def has_scope(self) -> bool:
        """True when at least one include rule is configured."""
        return bool(self.include_rules)

    def is_allowed(self, hostname: str) -> bool:
        """Return True when *hostname* is authorized by this scope."""
        target = normalize_hostname(hostname)
        if any(rule.matches(target) for rule in self.exclude_rules):
            return False
        return any(rule.matches(target) for rule in self.include_rules)

    def reject_reason(self, hostname: str) -> str | None:
        """Return a human-readable reason why a hostname is rejected, or None."""
        target = normalize_hostname(hostname)
        if any(rule.matches(target) for rule in self.exclude_rules):
            return f"{target} is explicitly excluded by scope"
        if not self.include_rules:
            return f"{target} is not authorized: program has no in-scope rules"
        if any(rule.matches(target) for rule in self.include_rules):
            return None
        return f"{target} is not authorized by any in-scope rule"

    def filter(self, hostnames: Iterator[str]) -> Iterator[str]:
        """Yield only the hostnames that are in scope."""
        for hostname in hostnames:
            if self.is_allowed(hostname):
                yield hostname

    def __len__(self) -> int:
        return len(self.include_rules) + len(self.exclude_rules)


__all__ = ["ScopeValidator", "ScopeRule"]
