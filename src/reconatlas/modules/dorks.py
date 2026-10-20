"""Search-engine dork generation.

The tool does not scrape search engines (that breaks their terms of service
and gets IP-blocked). Instead it generates a curated list of high-signal
queries for a target that you can paste into your favourite engine, or open
directly in a browser with ``--open``.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ..models import Finding
from .base import finding

#: (label, template) pairs. ``{t}`` is replaced by the target.
DORKS: tuple[tuple[str, str], ...] = (
    ("Files with sensitive extensions", 'site:{t} filetype:pdf | filetype:xls | filetype:doc'),
    ("Directory listings", 'site:{t} intitle:"index of"'),
    ("Config and backup files", 'site:{t} inurl:backup | inurl:config | inurl:settings'),
    ("Login and admin panels", 'site:{t} inurl:login | inurl:admin | inurl:signin'),
    ("Exposed git repositories", 'site:{t} inurl:.git'),
    ("Environment and secret files", 'site:{t} inurl:.env | inurl:secrets | inurl:credentials'),
    ("API endpoints", 'site:{t} inurl:api | inurl:graphql | inurl:swagger'),
    ("Error messages leaking paths", 'site:{t} "Traceback" | "stack trace" | "ORA-" | "SQLSTATE"'),
    ("Internal hosts in source", 'site:{t} "10.0." | "192.168." | "172.16."'),
    ("Email addresses on the site", 'site:{t} "@{t}"'),
    ("Shared documents", 'site:{t} filetype:docx | filetype:xlsx | filetype:pptx'),
    ("Archives and backups", 'site:{t} filetype:zip | filetype:tar | filetype:rar | filetype:7z'),
    ("Database dumps", 'site:{t} filetype:sql | filetype:dump | filetype:bak'),
    ("Password and key files", 'site:{t} inurl:id_rsa | inurl:credentials | inurl:key'),
    ("PHP info pages", 'site:{t} inurl:phpinfo'),
    ("Web server info pages", 'site:{t} inurl:server-status | inurl:server-info'),
    ("Pages mentioning the brand name", 'site:{t} "{t}"'),
)

#: Queries that work against the whole web rather than a single site.
GLOBAL_DORKS: tuple[tuple[str, str], ...] = (
    ("Mentions of the domain", '"{t}"'),
    ("Domain with a PDF", '"www.{t}" filetype:pdf'),
    ("Domain with an XLSX", '"www.{t}" filetype:xlsx'),
    ("Open documents on other domains", '"@{t}" filetype:pdf | filetype:xls'),
    ("Credential material", '"{t}" (password | passwd | credential)'),
    ("Database connection strings", '"{t}" ("jdbc:" | "mongodb://" | "postgres://" | "mysql://")'),
    ("Access keys and tokens", '"{t}" ("AKIA" | "api_key" | "secret_key" | "access_token")'),
    ("Paste sites mentioning the domain", 'site:pastebin.com "{t}" | site:paste.ee "{t}"'),
    ("Code repositories mentioning the domain", 'site:github.com "{t}" | site:gitlab.com "{t}"'),
    ("Job postings revealing infrastructure", 'site:linkedin.com/jobs "{t}"'),
)

ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/html/?q={q}",
    "yandex": "https://yandex.com/search/?text={q}",
    "startpage": "https://www.startpage.com/sp/search?query={q}",
    "brave": "https://search.brave.com/search?q={q}",
}


def _dork_target(target: str) -> str:
    """Reduce the target to the bare registrable domain.

    ``site:example.com`` also covers every subdomain in a search engine,
    which is what a dork wants, so the host is stripped down further than
    a plain URL cleanup would.
    """
    from ..util.net import registrable_domain

    cleaned = target.strip()
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", cleaned)
    cleaned = cleaned.split("/")[0]
    return registrable_domain(cleaned)


def build_dorks(target: str, *, global_scope: bool = True) -> list[tuple[str, str]]:
    """Return ``(label, query)`` pairs for *target*."""
    host = _dork_target(target)
    out: list[tuple[str, str]] = [
        (label, template.format(t=host)) for label, template in DORKS
    ]
    if global_scope:
        out.extend((label, template.format(t=host)) for label, template in GLOBAL_DORKS)
    return out


def collect_dorks(target: str, *, global_scope: bool = True) -> tuple[list[Finding], dict[str, Any]]:
    """Produce dork findings for *target*."""
    findings: list[Finding] = []
    host = _dork_target(target)

    for label, query in build_dorks(target, global_scope=global_scope):
        encoded = urllib.parse.quote_plus(query)
        findings.append(
            finding(
                "dork",
                label,
                query,
                source="generated",
                severity="info",
                search_url=ENGINES["google"].format(q=encoded),
            )
        )

    summary: dict[str, Any] = {
        "target": host,
        "dorks": len(findings),
        "engines": list(ENGINES),
    }
    return findings, summary
