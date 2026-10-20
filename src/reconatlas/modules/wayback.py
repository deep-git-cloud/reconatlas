"""Historical snapshot data from the Wayback Machine (archive.org CDX API)."""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..models import Finding
from ..util.text import parse_ts
from .base import finding

CDX_URL = "https://web.archive.org/cdx/search/cdx"

#: Columns returned by the CDX API when ``fl`` is not specified.
DEFAULT_FIELDS = "urlkey,timestamp,original,mimetype,statuscode,length"

#: Upper bound on the number of rows pulled for counting purposes.
COUNT_LIMIT = 20000


def _timestamps(http: HttpClient, url: str, limit: int, reverse: bool = False) -> list[str]:
    """Fetch timestamp values for a CDX query, newest or oldest first.

    The CDX API returns the oldest captures first unless ``sort=reverse``
    is given, so the most recent capture needs its own query.
    """
    params: dict[str, str] = {
        "url": url,
        "output": "json",
        "fl": "timestamp",
        "collapse": "timestamp:8",  # one snapshot per day
        "limit": str(limit),
    }
    if reverse:
        params["sort"] = "reverse"

    payload = http.get_json(CDX_URL, params=params)
    if not isinstance(payload, list) or len(payload) < 2:
        return []
    return [str(row[0]) for row in payload[1:] if isinstance(row, list) and row]


def collect_wayback(
    domain: str,
    http: HttpClient,
    *,
    limit: int = 40,
    subdomains: bool = False,
) -> tuple[list[Finding], dict[str, Any]]:
    """Summarise what the Internet Archive has archived for *domain*."""
    findings: list[Finding] = []
    target = f"*.{domain}" if subdomains else domain

    params = {
        "url": target,
        "output": "json",
        "fl": DEFAULT_FIELDS,
        "collapse": "timestamp:8",  # one snapshot per day
        "limit": str(limit),
    }

    fetch = http.get(CDX_URL, params=params)
    payload = fetch.json() if fetch.ok else None

    if not isinstance(payload, list) or len(payload) < 2:
        return findings, {"error": "no archived snapshots found"}

    header = payload[0]
    rows = payload[1:]

    index = {name: i for i, name in enumerate(header)}
    first_seen = last_seen = None
    total = 0
    unique_urls: set[str] = set()
    status_counts: dict[str, int] = {}

    for row in rows:
        if not isinstance(row, list) or len(row) < len(header):
            continue
        timestamp = str(row[index.get("timestamp", 1)])
        original = str(row[index.get("original", 2)])
        status = str(row[index.get("statuscode", 4)])

        total += 1
        unique_urls.add(original)
        status_counts[status] = status_counts.get(status, 0) + 1

        if first_seen is None or timestamp < first_seen:
            first_seen = timestamp
        if last_seen is None or timestamp > last_seen:
            last_seen = timestamp

    # The sample above is capped, so the true first and last captures are
    # fetched separately.
    all_timestamps = _timestamps(http, target, COUNT_LIMIT)
    snapshot_total = len(all_timestamps)
    truncated = snapshot_total >= COUNT_LIMIT

    if all_timestamps:
        earliest = all_timestamps[0]
        first_seen = earliest if first_seen is None else min(first_seen, earliest)

    newest = _timestamps(http, target, 1, reverse=True)
    if newest:
        last_seen = newest[0] if last_seen is None else max(last_seen, newest[0])

    if first_seen:
        findings.append(
            finding("wayback", "First snapshot", parse_ts(first_seen), source="Wayback Machine",
                    severity="info", note="Earliest capture held by the Internet Archive.")
        )
    if last_seen:
        findings.append(
            finding("wayback", "Most recent snapshot", parse_ts(last_seen), source="Wayback Machine",
                    severity="info", note="Most recent capture held by the Internet Archive.")
        )

    for status, count in sorted(status_counts.items(), key=lambda kv: -kv[1])[:8]:
        severity = "info"
        if status.startswith("3"):
            severity = "info"
        elif status.startswith("4") or status.startswith("5"):
            severity = "warn"
        findings.append(
            finding("wayback", f"HTTP {status}", f"{count} snapshot(s)", source="Wayback Machine",
                    severity=severity)
        )

    # Show a handful of interesting archived paths (not just the home page).
    interesting = [u for u in sorted(unique_urls) if u.rstrip("/").count("/") > 2][:25]
    for url in interesting:
        findings.append(finding("wayback", "Archived URL", url, source="Wayback Machine"))

    summary: dict[str, Any] = {
        "domain": domain,
        "snapshots_sampled": total,
        "total_snapshots": f"{snapshot_total}+" if truncated else snapshot_total,
        "unique_urls": len(unique_urls),
        "first_seen": parse_ts(first_seen) if first_seen else "",
        "last_seen": parse_ts(last_seen) if last_seen else "",
    }
    return findings, summary
