"""Console rendering and JSON/CSV export."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, ModuleResult, Report

SEVERITY_STYLE = {
    "info": "cyan",
    "good": "green",
    "warn": "yellow",
    "risk": "red",
    "critical": "bold red",
}

SEVERITY_GLYPH = {
    "info": "•",
    "good": "+",
    "warn": "!",
    "risk": "x",
    "critical": "!!",
}


def severity_of(finding: Finding) -> str:
    """Map a finding's severity onto a known level."""
    severity = (finding.severity or "info").lower()
    return severity if severity in SEVERITY_STYLE else "info"


class ConsoleRenderer:
    """Renders a :class:`Report` to the terminal with :mod:`rich`."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    # ------------------------------------------------------------------ parts

    def _finding_table(self, findings: Sequence[Finding]) -> Table:
        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            expand=True,
            pad_edge=False,
        )
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Field", style="bold cyan", no_wrap=True, ratio=1)
        table.add_column("Value", overflow="fold", ratio=3)
        table.add_column("Source", style="dim", no_wrap=True, ratio=1)

        for finding in findings:
            level = severity_of(finding)
            style = SEVERITY_STYLE[level]
            value = finding.value
            if finding.note:
                value = f"{value}\n[dim]{finding.note}[/dim]"
            table.add_row(
                Text(SEVERITY_GLYPH[level], style=style),
                Text(finding.key, style="cyan"),
                Text.from_markup(value) if "[" in value else Text(value),
                Text(finding.source or "-", style="dim"),
            )
        return table

    def _module_panel(self, name: str, result: ModuleResult) -> Panel:
        body_parts: list[Any] = []
        if result.summary:
            summary = ", ".join(f"{k}={v}" for k, v in result.summary.items() if v not in (None, "", [], {}))
            if summary:
                body_parts.append(Text(summary, style="dim"))
                body_parts.append(Text(""))
        if result.findings:
            body_parts.append(self._finding_table(result.findings))
        if result.errors:
            body_parts.append(Text(""))
            for err in result.errors:
                body_parts.append(Text(f"error: {err}", style="red"))

        if not body_parts:
            body_parts.append(Text("no results", style="dim"))

        status_colour = {"ok": "green", "partial": "yellow", "error": "red", "skipped": "dim"}.get(
            result.status, "cyan"
        )
        title = Text.assemble(
            (f" {name} ", "bold white"),
            (f"[{result.status}]", status_colour),
        )
        return Panel(Group(*body_parts), title=title, border_style=status_colour, padding=(0, 1))

    # ----------------------------------------------------------------- public

    def render(self, report: Report, show_empty: bool = False) -> None:
        """Print the whole report."""
        header = Text.assemble(
            ("\nOSINT report for ", "bold"),
            (report.target, "bold cyan"),
            (f"  ({report.target_type})", "dim"),
        )
        self.console.print(header)
        self.console.print(Text(f"started {report.started_at}", style="dim"))
        self.console.print()

        if not report.modules:
            self.console.print(Text("nothing collected", style="yellow"))
            return

        for name, result in report.modules.items():
            if not show_empty and not result.findings and not result.errors:
                continue
            self.console.print(self._module_panel(name, result))
            self.console.print()

    def render_summary(self, report: Report) -> None:
        """A compact one-line-per-module summary."""
        table = Table(show_header=True, header_style="bold magenta", border_style="dim")
        table.add_column("Module", style="bold cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Findings", justify="right", no_wrap=True)
        table.add_column("Errors", justify="right", no_wrap=True)
        table.add_column("Time", justify="right", no_wrap=True)

        from .util.text import human_duration

        for name, result in report.modules.items():
            status = result.status
            colour = {"ok": "green", "partial": "yellow", "error": "red", "skipped": "dim"}.get(
                status, "cyan"
            )
            table.add_row(
                name,
                Text(status, style=colour),
                str(len(result.findings)),
                str(len(result.errors)),
                human_duration(result.duration),
            )
        self.console.print(table)


# --------------------------------------------------------------------- export


def export_json(report: Report, path: str | Path) -> Path:
    """Write the full report as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.to_json(), encoding="utf-8")
    return path


def export_csv(report: Report, path: str | Path) -> Path:
    """Write every finding as a flat CSV row."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["target", "module", "category", "key", "value", "source", "severity", "note", "meta"]
        )
        for module_name, result in report.modules.items():
            for finding in result.findings:
                writer.writerow(
                    [
                        report.target,
                        module_name,
                        finding.category,
                        finding.key,
                        finding.value,
                        finding.source,
                        finding.severity,
                        finding.note,
                        json.dumps(finding.meta, default=str) if finding.meta else "",
                    ]
                )
    return path


def export_jsonl(report: Report, path: str | Path) -> Path:
    """Write every finding as one JSON object per line."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for module_name, result in report.modules.items():
            for finding in result.findings:
                record = finding.to_dict()
                record["module"] = module_name
                record["target"] = report.target
                handle.write(json.dumps(record, default=str) + "\n")
    return path


def export_html(report: Report, path: str | Path) -> Path:
    """Write a small, self-contained HTML report."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def esc(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    blocks: list[str] = []
    for module_name, result in report.modules.items():
        rows = []
        for finding in result.findings:
            rows.append(
                "<tr>"
                f"<td><span class='sev {severity_of(finding)}'>{esc(finding.key)}</span></td>"
                f"<td>{esc(finding.value)}</td>"
                f"<td class='src'>{esc(finding.source)}</td>"
                f"<td class='note'>{esc(finding.note)}</td>"
                "</tr>"
            )
        blocks.append(
            f"<section><h2>{esc(module_name)} "
            f"<small>{esc(result.status)} · {len(result.findings)} findings</small></h2>"
            "<table><thead><tr><th>Field</th><th>Value</th><th>Source</th><th>Note</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=4>no results</td></tr>'}</tbody></table>"
            "</section>"
        )

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>OSINT report - {esc(report.target)}</title>
<style>
 :root {{ color-scheme: dark; }}
 body {{ background:#11131a; color:#e6e6e6; font-family:ui-sans-serif,system-ui,sans-serif; margin:2rem; }}
 h1 {{ font-size:1.4rem; margin-bottom:.2rem; }}
 .meta {{ color:#8b8fa3; font-size:.85rem; margin-bottom:2rem; }}
 section {{ margin-bottom:2.5rem; }}
 h2 {{ font-size:1.05rem; border-bottom:1px solid #2a2e3d; padding-bottom:.4rem; }}
 h2 small {{ color:#8b8fa3; font-weight:400; margin-left:.5rem; }}
 table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
 th {{ text-align:left; color:#a78bfa; font-size:.78rem; text-transform:uppercase; padding:.4rem .6rem; }}
 td {{ padding:.35rem .6rem; border-top:1px solid #1e2130; vertical-align:top; }}
 .src {{ color:#6f7488; font-size:.8rem; white-space:nowrap; }}
 .note {{ color:#9aa0b4; font-size:.82rem; }}
 .sev {{ display:inline-block; padding:.1rem .45rem; border-radius:4px; font-size:.78rem; }}
 .sev.info {{ background:#1b2a3a; color:#7cc4ff; }}
 .sev.good {{ background:#12291d; color:#57d38c; }}
 .sev.warn {{ background:#2e2612; color:#e0b252; }}
 .sev.risk {{ background:#33191b; color:#f2726f; }}
 .sev.critical {{ background:#3d1114; color:#ff8b8b; font-weight:700; }}
</style></head><body>
<h1>{esc(report.target)}</h1>
<div class="meta">type {esc(report.target_type)} · started {esc(report.started_at)}</div>
{''.join(blocks)}
</body></html>"""
    path.write_text(html, encoding="utf-8")
    return path
