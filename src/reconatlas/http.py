"""HTTP plumbing shared by every network module.

The client provides:
  * a persistent :class:`requests.Session` with sane connection pooling
  * transparent on-disk caching (so repeated runs are fast and gentle)
  * per-host rate limiting to stay a good citizen on public APIs
  * retries with exponential backoff for transient failures
  * a :class:`Fetch` result type that never raises on network errors
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Config

#: How long a failed response stays cached, in seconds. Short, so that a
#: recovered API is picked up on the next run instead of after a full TTL.
ERROR_CACHE_TTL = 60


@dataclass
class Fetch:
    """The outcome of a single HTTP request."""

    url: str
    status: int = 0
    ok: bool = False
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0
    cached: bool = False
    final_url: str = ""

    def json(self) -> Any:
        """Parse the body as JSON, returning ``None`` when it is not valid."""
        if not self.text:
            return None
        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class _HostThrottle:
    """Tracks the last request time per host so we never burst a single API."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.min_interval <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                last = self._last.get(host, 0.0)
                delay = self.min_interval - (now - last)
                if delay <= 0:
                    self._last[host] = now
                    return
            time.sleep(min(delay, 5.0))


class HttpClient:
    """A polite, cached, retrying HTTP client."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": cfg.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        retry = Retry(
            total=cfg.retries,
            connect=cfg.retries,
            read=cfg.retries,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=32,
            pool_maxsize=32,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._throttle = _HostThrottle(cfg.rate_limit)
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------ cache

    def _cache_path(self, url: str, params: Mapping[str, Any] | None) -> Path:
        raw = url + "?" + json.dumps(params or {}, sort_keys=True)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        folder = self.cfg.cache_dir / digest[:2]
        return folder / f"{digest}.json"

    def _read_cache(self, path: Path) -> Fetch | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        if self.cfg.cache_ttl <= 0:
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

        # An explicit expiry lets error responses be cached briefly without
        # pinning a transient failure for the whole cache lifetime.
        expires = payload.get("expires_at")
        if expires is not None:
            if time.time() >= float(expires):
                return None
        elif (time.time() - stat.st_mtime) > self.cfg.cache_ttl:
            return None

        return Fetch(
            url=payload.get("url", ""),
            status=payload.get("status", 0),
            ok=payload.get("ok", False),
            text=payload.get("text", ""),
            headers=payload.get("headers", {}),
            error=payload.get("error", ""),
            elapsed=payload.get("elapsed", 0.0),
            cached=True,
            final_url=payload.get("final_url", ""),
        )

    def _write_cache(self, path: Path, fetch: Fetch) -> None:
        if self.cfg.no_cache or self.cfg.cache_ttl <= 0:
            return
        ttl = self.cfg.cache_ttl
        if not fetch.ok:
            # Failures expire quickly so a recovered API is picked up at once.
            ttl = min(ttl, ERROR_CACHE_TTL)
        payload = {
            "url": fetch.url,
            "status": fetch.status,
            "ok": fetch.ok,
            "text": fetch.text,
            "headers": fetch.headers,
            "error": fetch.error,
            "elapsed": fetch.elapsed,
            "final_url": fetch.final_url,
            "expires_at": time.time() + ttl,
        }
        with self._cache_lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload), encoding="utf-8")
            except OSError:
                pass

    # ------------------------------------------------------------------ fetch

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        cache: bool = True,
        timeout: float | None = None,
        allow_redirects: bool = True,
        method: str = "GET",
    ) -> Fetch:
        """Perform a request and return a :class:`Fetch` (never raises)."""
        cache_path = self._cache_path(url, params)
        if cache and not self.cfg.no_cache:
            cached = self._read_cache(cache_path)
            if cached is not None:
                return cached

        host = requests.utils.urlparse(url).netloc or url
        self._throttle.wait(host)

        started = time.monotonic()
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                headers=dict(headers or {}),
                timeout=(self.cfg.connect_timeout, timeout or self.cfg.timeout),
                allow_redirects=allow_redirects,
            )
        except requests.RequestException as exc:
            fetch = Fetch(
                url=url,
                error=f"{type(exc).__name__}: {exc}",
                elapsed=time.monotonic() - started,
            )
            if cache:
                self._write_cache(cache_path, fetch)
            return fetch

        fetch = Fetch(
            url=url,
            status=response.status_code,
            ok=response.status_code < 400,
            text=response.text,
            headers=dict(response.headers),
            elapsed=time.monotonic() - started,
            final_url=response.url,
        )
        if cache:
            self._write_cache(cache_path, fetch)
        return fetch

    def get_json(self, url: str, **kwargs: Any) -> Any:
        """GET a URL and decode the body as JSON (``None`` on any failure)."""
        return self.get(url, **kwargs).json()

    def get_text(self, url: str, **kwargs: Any) -> str:
        return self.get(url, **kwargs).text

    def head(self, url: str, **kwargs: Any) -> Fetch:
        kwargs.setdefault("cache", True)
        return self.get(url, method="HEAD", **kwargs)

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass
