"""Email address analysis: mail routing, SPF/DMARC, Gravatar, disposability."""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..models import Finding
from ..util.net import DISPOSABLE_DOMAINS, is_email, registrable_domain
from ..util.text import gravatar_hash
from .base import finding
from .dns import DnsResolver, parse_mx

#: Selectors commonly used for DKIM keys.
DKIM_SELECTORS = (
    "default", "selector1", "selector2", "google", "k1", "s1", "s2",
    "mail", "dkim", "smtp", "mandrill", "amazonses", "sparkpost", "zoho",
    "protonmail", "everlytickey", "mte1", "mte2", "pm",
)


def _dmarc_policy(policy: str) -> tuple[str, str]:
    """Grade a DMARC record."""
    if "p=reject" in policy:
        return "good", "Strongest enforcement (reject)"
    if "p=quarantine" in policy:
        return "warn", "Partial enforcement (quarantine)"
    if "p=none" in policy:
        return "warn", "Monitoring only (p=none)"
    if "pct=" in policy:
        return "warn", "Partial enforcement (pct)"
    return "info", "No p= tag found"


def _spf_policy(record: str) -> tuple[str, str]:
    lowered = record.lower()
    if "-all" in lowered:
        return "good", "Hard fail (-all)"
    if "~all" in lowered:
        return "warn", "Soft fail (~all)"
    if "?all" in lowered:
        return "warn", "Neutral (?all)"
    if "+all" in lowered:
        return "risk", "Permissive (+all) - allows any sender"
    if "redirect=" in lowered:
        return "good", "Delegated via redirect= to another policy"
    if "include:" in lowered:
        return "good", "Authorised senders via include: mechanisms"
    return "info", "No all mechanism found"


def collect_email(
    email: str, http: HttpClient, resolver: DnsResolver | None = None
) -> tuple[list[Finding], dict[str, Any]]:
    """Analyse an email address without sending anything to it."""
    findings: list[Finding] = []
    summary: dict[str, Any] = {"email": email}

    email = email.strip()
    if not is_email(email):
        return findings, {"error": "not a syntactically valid email address"}

    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    summary["domain"] = domain
    summary["local_part"] = local

    findings.append(finding("email", "Address", email, source="input"))
    if len(local) > 64 or len(email) > 254:
        findings.append(
            finding("email", "Length", "exceeds RFC limits", source="local check", severity="warn")
        )

    # ------------------------------------------------------ disposable
    if domain in DISPOSABLE_DOMAINS:
        findings.append(
            finding(
                "email",
                "Disposable",
                "yes",
                source="local list",
                severity="warn",
                note="Throwaway address; treat the identity as unverified.",
            )
        )
        summary["disposable"] = True
    else:
        summary["disposable"] = False

    # --------------------------------------------------------- mail routing
    resolver = resolver or DnsResolver(http)
    mx, error = resolver.resolve(domain, "MX")
    if mx:
        for record in mx:
            priority, exchange = parse_mx(record)
            if not exchange:
                findings.append(
                    finding(
                        "email",
                        "MX",
                        "null MX",
                        source="dns.google (DoH)",
                        severity="warn",
                        note="Null MX (RFC 7505): this domain accepts no mail at all.",
                    )
                )
            else:
                findings.append(
                    finding(
                        "email",
                        "MX",
                        exchange,
                        source="dns.google (DoH)",
                        note=f"priority {priority}",
                    )
                )
        summary["mx_count"] = len(mx)
    else:
        findings.append(
            finding(
                "email",
                "MX",
                "none found",
                source="dns.google (DoH)",
                severity="risk",
                note="The domain has no mail exchangers, so mail to it cannot be delivered."
                if error != "NXDOMAIN"
                else "The domain does not exist in DNS.",
            )
        )
        summary["mx_count"] = 0

    # --------------------------------------------------------------- SPF
    txt, _ = resolver.resolve(domain, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if spf:
        record = spf[0]
        severity, note = _spf_policy(record)
        findings.append(
            finding("email", "SPF", record[:250], source="dns.google (DoH)", severity=severity, note=note)
        )
        summary["spf"] = record[:250]
    else:
        findings.append(
            finding("email", "SPF", "not configured", source="dns.google (DoH)", severity="warn")
        )

    # ------------------------------------------------------------- DMARC
    dmarc_records, _ = resolver.resolve(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_records if "v=DMARC1" in t]
    if dmarc:
        record = dmarc[0]
        severity, note = _dmarc_policy(record)
        findings.append(
            finding("email", "DMARC", record[:250], source="dns.google (DoH)", severity=severity, note=note)
        )
        summary["dmarc"] = record[:250]
    else:
        findings.append(
            finding("email", "DMARC", "not configured", source="dns.google (DoH)", severity="warn")
        )

    # -------------------------------------------------------------- DKIM
    # DKIM selectors are per-domain and cannot be enumerated without zone
    # access, so the common ones are tried. The record tells you the
    # selector to look up if this reports nothing.
    dkim_found = False
    for selector in DKIM_SELECTORS:
        records, _ = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
        if any("p=" in r for r in records):
            findings.append(
                finding("email", "DKIM", f"selector: {selector}", source="dns.google (DoH)", severity="good")
            )
            dkim_found = True
            break
    if not dkim_found:
        findings.append(
            finding(
                "email",
                "DKIM",
                "no common selector found",
                source="dns.google (DoH)",
                severity="info",
                note="Selectors are domain specific; check the sender's DNS records for the exact one.",
            )
        )
    summary["dkim"] = dkim_found

    # ----------------------------------------------------------- BIMI
    bimi, _ = resolver.resolve(f"default._bimi.{domain}", "TXT")
    if bimi:
        findings.append(
            finding("email", "BIMI", bimi[0][:200], source="dns.google (DoH)", severity="good")
        )

    # ---------------------------------------------------------- MX fallback
    if not mx:
        a_records, _ = resolver.resolve(domain, "A")
        if a_records:
            findings.append(
                finding(
                    "email",
                    "Implicit MX",
                    f"RFC 5321 fallback to A record {a_records[0]}",
                    source="dns.google (DoH)",
                    severity="info",
                )
            )

    # ---------------------------------------------------------- Gravatar
    digest = gravatar_hash(email)
    profile = http.get_json(f"https://gravatar.com/{digest}.json")
    if isinstance(profile, dict) and profile.get("entry"):
        entry = profile["entry"][0]
        summary["gravatar"] = True
        findings.append(
            finding("email", "Gravatar", "profile exists", source="Gravatar", severity="info",
                    note="The address is registered to a Gravatar profile.")
        )
        for field in ("displayName", "currentLocation", "currentEmployer", "aboutMe", "username"):
            value = entry.get(field)
            if value:
                findings.append(
                    finding("email", f"Gravatar {field}", str(value)[:200], source="Gravatar")
                )
    else:
        summary["gravatar"] = False

    # ------------------------------------------- domain registration hints
    summary["registrable_domain"] = registrable_domain(domain)
    return findings, summary
