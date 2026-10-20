"""Data model shared by collectors, renderers and exporters."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

# Severity levels used to colour the console output.
SEVERITIES = ("info", "good", "warn", "risk", "critical")


def utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Finding:
    """A single observation produced by a collector."""

    category: str
    """Logical group, e.g. ``dns``, ``subdomain``, ``cert``."""

    key: str
    """Short label for the value, e.g. the record type or platform name."""

    value: str
    """The observed value, e.g. an IP address or a profile URL."""

    source: str = ""
    """Which public data source produced this finding."""

    severity: str = "info"
    note: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "note": self.note,
            "meta": self.meta,
        }


@dataclass
class ModuleResult:
    """Everything one collector learned about a target."""

    name: str
    status: str = "ok"  # ok | partial | error | skipped
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0
    summary: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def fail(self, message: str) -> None:
        self.errors.append(message)
        self.status = "partial" if self.findings else "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration": round(self.duration, 3),
            "summary": self.summary,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Report:
    """The aggregated output of one or more collectors."""

    target: str
    target_type: str = "unknown"
    started_at: str = field(default_factory=utcnow_iso)
    modules: dict[str, ModuleResult] = field(default_factory=dict)

    def add(self, result: ModuleResult) -> None:
        self.modules[result.name] = result

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for result in self.modules.values():
            out.extend(result.findings)
        return out

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "modules": {name: res.to_dict() for name, res in self.modules.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
