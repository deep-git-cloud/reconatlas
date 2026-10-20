"""Username enumeration across public platforms.

Two strategies are used:
  * ``api`` platforms - a JSON endpoint returns structured profile data, so
    the result is reliable.
  * ``http`` platforms - the profile page is fetched and the status code
    plus page content are used to decide whether the account exists.

HTTP checks are heuristic: a 200 response can still be a soft-404, so the
confidence is reported alongside the result.
"""

from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ..http import Fetch, HttpClient
from ..models import Finding
from ..util.text import gravatar_hash
from .base import finding


@dataclass(frozen=True)
class Platform:
    name: str
    url: str
    api: str | None = None
    api_kind: str = "json"
    method: str = "GET"
    check_url_in_body: bool = True


PLATFORMS: tuple[Platform, ...] = (
    Platform("GitHub", "https://github.com/{u}", "https://api.github.com/users/{u}"),
    Platform("GitLab", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}"),
    Platform("Bitbucket", "https://bitbucket.org/{u}/", "https://api.bitbucket.org/2.0/users/{u}"),
    Platform("Codeberg", "https://codeberg.org/{u}", "https://codeberg.org/api/v1/users/{u}"),
    Platform("PyPI", "https://pypi.org/user/{u}", "https://pypi.org/pypi/{u}/json"),
    Platform("npm", "https://www.npmjs.com/~{u}"),
    Platform("Docker Hub", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/"),
    Platform("Hugging Face", "https://huggingface.co/{u}", "https://huggingface.co/api/username/{u}"),
    Platform("Kaggle", "https://www.kaggle.com/{u}", "https://www.kaggle.com/api/v1/users/list?search={u}"),
    Platform("Dev.to", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}"),
    Platform("Hacker News", "https://news.ycombinator.com/user?id={u}",
             "https://hacker-news.firebaseio.com/v0/user/{u}.json"),
    Platform("Keybase", "https://keybase.io/{u}",
             "https://keybase.io/_/api/1.0/user/lookup.json?username={u}"),
    Platform("Reddit", "https://www.reddit.com/user/{u}",
             "https://www.reddit.com/user/{u}/about.json"),
    Platform("Replit", "https://replit.com/@{u}"),
    Platform("GitHub Gist", "https://gist.github.com/{u}"),
    Platform("Instagram", "https://www.instagram.com/{u}/"),
    Platform("X", "https://x.com/{u}"),
    Platform("TikTok", "https://www.tiktok.com/@{u}"),
    Platform("Facebook", "https://www.facebook.com/{u}"),
    Platform("Pinterest", "https://www.pinterest.com/{u}/"),
    Platform("Twitch", "https://www.twitch.tv/{u}"),
    Platform("YouTube", "https://www.youtube.com/@{u}"),
    Platform("Medium", "https://medium.com/@{u}"),
    Platform("Blogger", "https://{u}.blogspot.com"),
    Platform("Telegram", "https://t.me/{u}"),
    Platform("Steam", "https://steamcommunity.com/id/{u}"),
    Platform("SoundCloud", "https://soundcloud.com/{u}"),
    Platform("Flickr", "https://www.flickr.com/people/{u}"),
    Platform("Behance", "https://www.behance.net/{u}"),
    Platform("Dribbble", "https://dribbble.com/{u}"),
    Platform("Goodreads", "https://www.goodreads.com/{u}"),
    Platform("Patreon", "https://www.patreon.com/{u}"),
    Platform("Mastodon", "https://mastodon.social/@{u}"),
    Platform("Linktree", "https://linktr.ee/{u}"),
    Platform("Gravatar", "https://gravatar.com/{u}"),
    Platform("About.me", "https://about.me/{u}"),
    Platform("Slideshare", "https://www.slideshare.net/{u}"),
    Platform("Mixcloud", "https://www.mixcloud.com/{u}/"),
    Platform("Vimeo", "https://vimeo.com/{u}"),
    Platform("Last.fm", "https://www.last.fm/user/{u}"),
    Platform("Chess.com", "https://www.chess.com/member/{u}"),
    Platform("Roblox", "https://www.roblox.com/user.aspx?username={u}"),
)

#: Text that indicates a platform returned its generic "not found" page.
NOT_FOUND_MARKERS = (
    "not found",
    "page not found",
    "404",
    "doesn't exist",
    "does not exist",
    "no such user",
    "user not found",
    "this account doesn't exist",
    "sorry, this page isn't available",
    "content isn't available",
    "isn\u2019t available",
    "account not found",
    "no longer available",
    "nothing to see here",
)


def _looks_like_not_found(text: str) -> bool:
    lowered = text[:20000].lower()
    return any(marker in lowered for marker in NOT_FOUND_MARKERS)


def _check_api(platform: Platform, username: str, http: HttpClient) -> tuple[bool, str, dict[str, Any]]:
    """Query a platform's JSON API. Returns ``(exists, detail, meta)``."""
    url = platform.api.format(u=username)
    payload = http.get_json(url)
    if payload is None:
        return False, "", {}

    meta: dict[str, Any] = {}
    if isinstance(payload, list):
        if not payload:
            return False, "", {}
        payload = payload[0] if isinstance(payload[0], dict) else {}
    if not isinstance(payload, dict):
        return False, "", {}

    if "error" in payload and "message" in payload and not payload.get("id"):
        return False, str(payload.get("message"))[:120], meta

    if platform.name == "Dev.to":
        exists = "id" in payload
        if exists:
            meta = {
                "name": payload.get("name"),
                "joined": payload.get("joined_at"),
                "summary": (payload.get("summary") or "")[:200],
            }
        return exists, "", meta

    if platform.name == "Kaggle":
        return bool(payload), "", {}

    if platform.name == "Keybase":
        status = (payload.get("status") or {}).get("code")
        if status == 205:
            return False, "account not found", meta
        user = payload.get("user") or {}
        meta = {"name": user.get("full_name"), "username": user.get("username")}
        return True, "", meta

    if platform.name == "Hacker News":
        exists = bool(payload.get("id"))
        if exists:
            meta = {"karma": payload.get("karma"), "created": payload.get("created")}
        return exists, "", meta

    if platform.name == "npm registry":
        if "error" in payload:
            return False, str(payload.get("error"))[:120], meta
        meta = {"name": payload.get("name"), "email": payload.get("email")}
        return True, "", meta

    if platform.name == "PyPI":
        info = payload.get("info") or {}
        if not info:
            return False, "", meta
        meta = {"name": info.get("name"), "summary": (info.get("summary") or "")[:200]}
        return True, "", meta

    if platform.name == "Docker Hub":
        if "username" not in payload:
            return False, "", meta
        meta = {"name": payload.get("name"), "location": payload.get("location")}
        return True, "", meta

    if platform.name == "Hugging Face":
        if "error" in payload:
            return False, "", meta
        meta = {"name": payload.get("fullname"), "type": payload.get("type")}
        return True, "", meta

    if platform.name == "Reddit":
        data = payload.get("data") or {}
        if not data or data.get("is_suspended") and not data.get("name"):
            return False, "", meta
        meta = {
            "name": data.get("name"),
            "created": data.get("created_utc"),
            "karma": data.get("total_karma"),
        }
        return True, "", meta

    # Generic JSON profile endpoints (GitHub, GitLab, Bitbucket, Codeberg).
    identifier = (
        payload.get("login")
        or payload.get("username")
        or payload.get("name")
        or payload.get("id")
        or payload.get("full_name")
    )
    if identifier is None:
        return False, "", meta
    meta = {
        "name": payload.get("name") or payload.get("full_name") or payload.get("display_name"),
        "id": payload.get("id"),
    }
    if payload.get("bio"):
        meta["bio"] = str(payload["bio"])[:200]
    if payload.get("created_at"):
        meta["created"] = payload["created_at"]
    if payload.get("location"):
        meta["location"] = payload["location"]
    if payload.get("followers") is not None:
        meta["followers"] = payload["followers"]
    if payload.get("public_repos") is not None:
        meta["public_repos"] = payload["public_repos"]
    return True, "", meta


def _page_signals(body: str, final_url: str, username: str) -> dict[str, bool]:
    """Extract corroborating signals that a profile page really exists.

    A 200 response is not proof - plenty of sites answer unknown profiles
    with a generic landing page. We look for the handle in the canonical
    URL, the ``og:url`` tag, or the final URL, which a soft-404 will not
    contain.
    """
    handle = username.lower()
    final_lower = (final_url or "").lower()

    canonical = ""
    og_url = ""
    for pattern, target in (
        (r"<link[^>]+rel=[\"']canonical[\"'][^>]*?href=[\"']([^\"']+)", "canonical"),
        (r"<meta[^>]+property=[\"']og:url[\"'][^>]*?content=[\"']([^\"']+)", "og"),
    ):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            if target == "canonical":
                canonical = match.group(1).lower()
            else:
                og_url = match.group(1).lower()

    # The path component of the final URL is what matters; a bare domain
    # means we were redirected to a landing page.
    path = final_lower.split("//", 1)[-1].split("/", 1)[-1] if "//" in final_lower else ""
    path = path.split("?", 1)[0]

    return {
        "canonical_has_handle": handle in canonical,
        "og_url_has_handle": handle in og_url,
        "url_has_handle": handle in path,
        "url_is_generic": path.strip("/") in {"", "login", "signin", "signup", "error", "404"},
        "body_has_handle": handle in body.lower(),
    }


def _control_username() -> str:
    """A username that is extremely unlikely to exist anywhere."""
    return "zzq" + uuid.uuid4().hex[:12]


def _differential_check(
    platform: Platform,
    username: str,
    http: HttpClient,
    target_fetch: "Fetch | None" = None,
) -> tuple[bool, str]:
    """Compare the profile page with a control page for a random handle.

    Single-page applications happily return HTTP 200 for handles that do
    not exist, so the only reliable test is to compare the target page
    against a page for a handle that certainly does not exist. Control
    pages are byte-for-byte stable in practice, so a meaningful size
    difference means the target really is a profile.
    """
    control = _control_username()
    if target_fetch is None:
        target_fetch = http.get(platform.url.format(u=username))
    control_fetch = http.get(platform.url.format(u=control))

    if target_fetch.error or control_fetch.error:
        return False, "inconclusive: control request failed"

    if target_fetch.status != control_fetch.status:
        return True, f"HTTP {target_fetch.status} vs {control_fetch.status} for a random handle"

    target_norm = target_fetch.text.lower().replace(username.lower(), "")
    control_norm = control_fetch.text.lower().replace(control.lower(), "")

    delta = len(target_norm) - len(control_norm)
    # Single-page apps serve several template variants that differ by a
    # kilobyte or two, so only a clearly larger page counts as a profile.
    threshold = max(5000, int(len(control_norm) * 0.02))

    if delta > threshold:
        return True, f"page is {delta} bytes larger than a non-existent account"
    if delta < -threshold:
        return False, f"page is {-delta} bytes smaller than a non-existent account"
    if target_norm.strip() == control_norm.strip():
        return False, "identical to a non-existent account"
    return False, "inconclusive: page is indistinguishable from a non-existent account"


def _check_http(platform: Platform, username: str, http: HttpClient) -> tuple[bool, str, dict[str, Any]]:
    """Probe a profile page and judge whether the account exists."""
    url = platform.url.format(u=username)
    fetch = http.get(url, allow_redirects=True)

    meta: dict[str, Any] = {"status": fetch.status, "final_url": fetch.final_url}
    if fetch.error:
        return False, fetch.error[:140], meta
    if fetch.status == 404:
        return False, "404", meta
    if fetch.status in (403, 429, 401):
        return False, f"blocked (HTTP {fetch.status}) - status unknown", meta
    if fetch.status >= 500:
        return False, f"server error (HTTP {fetch.status}) - status unknown", meta
    if fetch.status >= 400:
        return False, f"HTTP {fetch.status}", meta

    body = fetch.text
    if _looks_like_not_found(body):
        return False, "soft-404 page", meta

    signals = _page_signals(body, fetch.final_url, username)
    meta.update(signals)

    # The decisive test: compare against a page for a handle that cannot
    # exist. Canonical and og:url tags are checked too, but on their own
    # they are unreliable - several sites set them for unknown profiles.
    exists, detail = _differential_check(platform, username, http, fetch)
    meta["differential"] = detail

    if exists:
        return True, detail, meta
    if detail.startswith("inconclusive"):
        if signals["canonical_has_handle"] and signals["og_url_has_handle"]:
            return True, "weak signal: canonical and og:url match", meta
        return False, detail, meta
    return False, detail, meta


def _is_inconclusive(detail: str, meta: dict[str, Any]) -> bool:
    """True when the platform gave us no reliable answer either way."""
    if not detail:
        return True
    lowered = detail.lower()
    if lowered.startswith("inconclusive"):
        return True
    if "unknown" in lowered or "blocked" in lowered or "error" in lowered:
        return True
    # The handle appeared on the page but nothing proved it is a profile.
    if meta.get("body_has_handle") and not meta.get("canonical_has_handle"):
        return True
    return False


def check_username(
    username: str,
    http: HttpClient,
    *,
    platforms: tuple[Platform, ...] = PLATFORMS,
    concurrency: int = 8,
) -> tuple[list[Finding], dict[str, Any]]:
    """Check *username* against every known platform."""
    findings: list[Finding] = []
    username = username.strip().lstrip("@")

    def run(platform: Platform) -> tuple[Platform, bool, str, dict[str, Any]]:
        try:
            if platform.api:
                exists, detail, meta = _check_api(platform, username, http)
                if exists or detail:
                    return platform, exists, detail, meta
            return (platform, *(_check_http(platform, username, http)))
        except Exception as exc:  # noqa: BLE001
            return platform, False, f"{type(exc).__name__}: {exc}"[:140], {}

    hits: list[tuple[Platform, dict[str, Any]]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for platform, exists, detail, meta in pool.map(run, platforms):
            if exists:
                hits.append((platform, meta))
                note = ""
                if meta.get("name"):
                    note = str(meta["name"])
                findings.append(
                    finding(
                        "username",
                        platform.name,
                        platform.url.format(u=username),
                        source="public profile check",
                        severity="good" if platform.api else "info",
                        note=note,
                        confidence="high" if platform.api else "medium",
                        **meta,
                    )
                )
            elif _is_inconclusive(detail, meta):
                findings.append(
                    finding(
                        "username",
                        platform.name,
                        "inconclusive",
                        source="public profile check",
                        severity="info",
                        note=detail or "no reliable signal",
                        confidence="low",
                    )
                )
            else:
                findings.append(
                    finding(
                        "username",
                        platform.name,
                        "not found",
                        source="public profile check",
                        severity="info",
                        note=detail,
                        confidence="high" if platform.api else "medium",
                    )
                )

    summary: dict[str, Any] = {
        "username": username,
        "platforms_checked": len(platforms),
        "hits": len(hits),
    }

    # Gravatar works for email addresses, but the hash of the username is
    # a useful cross-check for people who reuse handles.
    digest = gravatar_hash(f"{username}@example.com")
    profile = http.get_json(f"https://gravatar.com/{digest}.json")
    if isinstance(profile, dict) and profile.get("entry"):
        summary["gravatar_hash_guess"] = digest

    return findings, summary


def platform_names() -> list[str]:
    return [p.name for p in PLATFORMS]
