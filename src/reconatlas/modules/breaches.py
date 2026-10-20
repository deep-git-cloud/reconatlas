"""Breach corpus lookups via the public Have I Been Pwned breach list.

The account-search endpoint requires a paid key, but the *breach corpus*
(``/api/v3/breaches``) is public and keyless. We download it once, cache it
and filter it locally, which reveals every known breach for a domain.
"""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..models import Finding
from ..util.net import registrable_domain
from .base import finding

BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
API_KEY_ENV = "OSINTKIT_HIBP_KEY"


def fetch_breaches(http: HttpClient) -> list[dict[str, Any]]:
    """Download the full public breach corpus."""
    payload = http.get_json(BREACHES_URL, headers={"hibp-api-key": ""})
    if isinstance(payload, list):
        return payload
    return []


def collect_breaches(
    domain: str,
    http: HttpClient,
    *,
    include_unverified: bool = True,
) -> tuple[list[Finding], dict[str, Any]]:
    """List every breach in the corpus that affects *domain*."""
    findings: list[Finding] = []
    target = registrable_domain(domain)
    breaches = fetch_breaches(http)
    if not breaches:
        return findings, {"error": "could not download the breach corpus"}

    matches = []
    for breach in breaches:
        breach_domain = str(breach.get("Domain") or "").lower()
        if not breach_domain:
            continue
        if breach_domain == target or target.endswith("." + breach_domain):
            matches.append(breach)

    if not include_unverified:
        matches = [b for b in matches if b.get("IsVerified")]

    matches.sort(key=lambda b: str(b.get("BreachDate") or ""), reverse=True)

    total = sum(int(b.get("PwnCount") or 0) for b in matches)
    for breach in matches:
        name = breach.get("Title") or breach.get("Name") or "unknown"
        count = int(breach.get("PwnCount") or 0)
        date = str(breach.get("BreachDate") or "")
        note_parts = []
        if date:
            note_parts.append(date)
        if breach.get("IsVerified") is False:
            note_parts.append("unverified")
        if breach.get("IsRetired"):
            note_parts.append("retired")
        if breach.get("IsSensitive"):
            note_parts.append("sensitive")
        classes = ", ".join(str(c) for c in (breach.get("DataClasses") or [])[:6])
        if classes:
            note_parts.append("data: " + classes)
        findings.append(
            finding(
                "breach",
                name,
                f"{count:,} accounts" if count else "account count unknown",
                source="Have I Been Pwned",
                severity="risk",
                note="; ".join(note_parts),
                breach_date=date,
                data_classes=breach.get("DataClasses") or [],
                domain=breach.get("Domain"),
            )
        )

    summary: dict[str, Any] = {
        "domain": target,
        "breaches": len(matches),
        "total_accounts": total,
        "corpus_size": len(breaches),
    }

    if matches:
        data_classes: dict[str, int] = {}
        for breach in matches:
            for item in breach.get("DataClasses") or []:
                data_classes[str(item)] = data_classes.get(str(item), 0) + 1
        if data_classes:
            summary["data_classes"] = data_classes

    return findings, summary
