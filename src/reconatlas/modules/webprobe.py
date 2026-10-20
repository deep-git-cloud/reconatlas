"""Web server probing: headers, technology fingerprint, and public files.

Also fetches the well-known files that leak useful information:
``robots.txt``, ``sitemap.xml``, ``security.txt`` and ``.well-known/*``.
"""

from __future__ import annotations

import re
from typing import Any

from ..http import HttpClient
from ..models import Finding
from ..util.net import normalize_url
from .base import finding

#: (header, friendly name) pairs whose presence reveals the stack.
TECH_HEADERS = (
    ("server", "Web server"),
    ("x-powered-by", "Powered by"),
    ("x-aspnet-version", "ASP.NET version"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-drupal-cache", "Drupal"),
    ("x-generator", "Generator"),
    ("x-telerik-traceid", "Telerik"),
    ("x-shopify-stage", "Shopify"),
    ("x-magento-tags", "Magento"),
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "AWS CloudFront"),
    ("x-github-request-id", "GitHub Pages"),
    ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"),
    ("x-served-by", "Fastly"),
    ("via", "Proxy chain"),
    ("x-varnish", "Varnish"),
)

#: Substrings in the ``Server`` header that name a specific product.
SERVER_HINTS = (
    ("nginx", "nginx"),
    ("apache", "Apache"),
    ("caddy", "Caddy"),
    ("lighttpd", "lighttpd"),
    ("iis", "Microsoft IIS"),
    ("litespeed", "LiteSpeed"),
    ("openresty", "OpenResty"),
    ("cloudflare", "Cloudflare"),
)

#: Body signatures used for technology fingerprinting.
BODY_SIGNATURES = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("_next/static", "Next.js"),
    ("__NEXT_DATA__", "Next.js"),
    ("_nuxt/", "Nuxt.js"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("vue.js", "Vue.js"),
    ("Drupal.settings", "Drupal"),
    ("joomla", "Joomla"),
    ("Shopify.theme", "Shopify"),
    ("cloudflare", "Cloudflare"),
    ("webpack", "webpack"),
    ("bootstrap.min.css", "Bootstrap"),
    ("jquery", "jQuery"),
    ("react", "React"),
    ("ASP.NET", "ASP.NET"),
    ("laravel_session", "Laravel"),
)

#: Interesting security headers, and what their absence means.
SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS", "warn"),
    ("content-security-policy", "CSP", "warn"),
    ("x-frame-options", "X-Frame-Options", "warn"),
    ("x-content-type-options", "X-Content-Type-Options", "warn"),
    ("referrer-policy", "Referrer-Policy", "info"),
    ("permissions-policy", "Permissions-Policy", "info"),
)

#: Paths worth probing for accidental exposure.
PROBE_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/phpinfo.php",
    "/wp-login.php",
    "/admin",
    "/.git/config",
    "/server-status",
    "/api/",
)


def _title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def _meta_tags(html: str, limit: int = 12) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in re.finditer(
        r"<meta\s+[^>]*?name=[\"']([^\"']+)[\"'][^>]*?content=[\"']([^\"']*)[\"']",
        html,
        re.IGNORECASE,
    ):
        name = match.group(1).lower()
        if name not in out:
            out[name] = match.group(2).strip()[:200]
        if len(out) >= limit:
            break
    for match in re.finditer(
        r"<meta\s+[^>]*?content=[\"']([^\"']*)[\"'][^>]*?name=[\"']([^\"']+)[\"']",
        html,
        re.IGNORECASE,
    ):
        name = match.group(2).lower()
        if name not in out:
            out[name] = match.group(1).strip()[:200]
        if len(out) >= limit:
            break
    return out


def _fingerprint(headers: dict[str, str], body: str) -> list[tuple[str, str]]:
    tech: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label: str, value: str) -> None:
        if label in seen or not value:
            return
        seen.add(label)
        tech.append((label, value))

    server = ""
    for key, value in headers.items():
        if key.lower() == "server":
            server = value
            break
    for needle, label in SERVER_HINTS:
        if needle in server.lower():
            add("Web server", server)
            break

    for header, label in TECH_HEADERS:
        if label == "Web server":
            # Already handled from the Server header above.
            continue
        value = headers.get(header) or headers.get(header.title())
        add(label, value)

    sample = body[:120_000].lower()
    for needle, label in BODY_SIGNATURES:
        if needle.lower() in sample:
            add("Detected", label)

    powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if powered and "PHP" in powered:
        add("Language", powered)

    return tech


def probe_site(
    url: str, http: HttpClient, *, deep: bool = False
) -> tuple[list[Finding], dict[str, Any]]:
    """Fetch a URL and describe what is running there."""
    findings: list[Finding] = []
    summary: dict[str, Any] = {}
    target = normalize_url(url)

    fetch = http.get(target, allow_redirects=True)
    if fetch.error:
        return findings, {"error": fetch.error}
    if fetch.status == 0:
        return findings, {"error": "no response"}
    if fetch.status >= 400:
        return findings, {"status": fetch.status, "error": f"HTTP {fetch.status}"}

    headers = {k: v for k, v in fetch.headers.items()}
    body = fetch.text
    summary["url"] = fetch.final_url or target
    summary["status"] = fetch.status
    summary["bytes"] = len(body)

    findings.append(
        finding("web", "Status", str(fetch.status), source="direct request",
                severity="good" if fetch.status < 300 else "info")
    )
    if fetch.final_url and fetch.final_url.rstrip("/") != target.rstrip("/"):
        findings.append(
            finding("web", "Redirected to", fetch.final_url, source="direct request",
                    note="The requested URL redirects elsewhere.")
        )

    title = _title(body)
    if title:
        findings.append(finding("web", "Page title", title, source="direct request"))
        summary["title"] = title

    for label, value in _fingerprint(headers, body):
        findings.append(finding("web", label, value, source="header/body fingerprint"))

    meta = _meta_tags(body)
    for name in ("generator", "author", "description", "robots", "viewport"):
        if name in meta:
            findings.append(finding("web", f"meta {name}", meta[name], source="page source"))

    # ------------------------------------------------- security headers
    for header, label, severity in SECURITY_HEADERS:
        value = headers.get(header) or headers.get(header.title())
        if value:
            findings.append(finding("web", label, value[:120], source="response header", severity="good"))
        else:
            findings.append(
                finding("web", label, "not set", source="response header", severity=severity)
            )

    # ------------------------------------------------- public files
    paths = PROBE_PATHS if deep else ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
    for path in paths:
        probe = http.get(target.rstrip("/") + path, allow_redirects=True)
        if probe.status == 0 or probe.error:
            continue
        if probe.status == 200 and probe.text.strip():
            snippet = probe.text.strip()[:400]
            severity = "risk" if path in ("/.git/HEAD", "/.env", "/.git/config") else "info"
            findings.append(
                finding(
                    "web",
                    f"Exposed file {path}",
                    snippet,
                    source="direct request",
                    severity=severity,
                    note="Publicly reachable path." if severity == "risk" else "",
                )
            )
        elif probe.status in (401, 403):
            findings.append(
                finding("web", f"Path {path}", f"HTTP {probe.status} (protected)",
                        source="direct request", severity="good")
            )

    return findings, summary
