"""Collector base class and shared context."""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..config import Config
from ..http import HttpClient
from ..models import Finding, ModuleResult


@dataclass
class Context:
    """Everything a collector needs to do its job."""

    config: Config
    http: HttpClient
    target: str
    target_type: str = "unknown"

    def log(self, message: str) -> None:
        if self.config.verbose:
            from rich.console import Console

            Console(stderr=True).print(f"[dim]{message}[/dim]")


class Collector:
    """Base class for all reconatlas collectors.

    Subclasses implement :meth:`collect` and return a populated
    :class:`~reconatlas.models.ModuleResult`.
    """

    #: Short name used on the command line and in reports.
    name: str = "collector"
    #: One-line description shown in ``--help``.
    description: str = ""

    def collect(self, ctx: Context) -> ModuleResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # ------------------------------------------------------------------ helper

    def run(self, ctx: Context) -> ModuleResult:
        """Run :meth:`collect`, converting unexpected errors into a result."""
        result = ModuleResult(name=self.name)
        started = time.monotonic()
        try:
            outcome = self.collect(ctx)
            if outcome is not None:
                result = outcome
        except Exception as exc:  # noqa: BLE001 - collectors must never crash a run
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.name = self.name
        result.duration = time.monotonic() - started
        return result


def finding(
    category: str,
    key: str,
    value: str,
    source: str = "",
    severity: str = "info",
    note: str = "",
    **meta: object,
) -> Finding:
    """Terse constructor for :class:`~reconatlas.models.Finding`."""
    return Finding(
        category=category,
        key=key,
        value=str(value),
        source=source,
        severity=severity,
        note=note,
        meta=dict(meta),
    )
