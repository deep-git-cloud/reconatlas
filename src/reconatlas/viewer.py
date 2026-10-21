"""Local browser view of live satellite positions.

The viewer is a single page served from loopback: no tiles, no CDN, no
account. The browser polls ``/api/positions``; the server reuses one
classified catalogue and only re-runs SGP4, so a refresh costs
milliseconds and never touches CelesTrak.

Security: it binds to 127.0.0.1 by default and only ever reads. Do not
expose it on a public interface.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .modules import satellite as sat

#: Served as-is; the page fetches everything else.
_ASSET_DIR = "data"


def asset_path(name: str) -> Any:
    """Resolve a bundled asset (works from a wheel or a source tree)."""
    return files("reconatlas").joinpath(_ASSET_DIR).joinpath(name)


@lru_cache(maxsize=4)
def read_asset(name: str) -> bytes:
    """Read a bundled asset once; the viewer serves them on every load."""
    return asset_path(name).read_bytes()


class ViewerState:
    """Everything the HTTP layer needs, shared across request threads."""

    def __init__(
        self,
        catalogue: sat.Catalogue,
        *,
        observer: sat.Observer | None = None,
        classes: tuple[str, ...] = (),
        match: str = "",
        limit: int = 0,
        overhead: bool = False,
        min_elevation: float = 0.0,
    ) -> None:
        self.catalogue = catalogue
        self.observer = observer
        self.classes = classes
        self.match = match
        self.limit = limit
        self.overhead = overhead
        self.min_elevation = min_elevation
        # One snapshot up front so /api/meta can describe the result.
        self._first, self._first_summary = sat.snapshot(
            catalogue,
            classes=classes,
            match=match,
            observer=observer,
            limit=limit,
            overhead=overhead,
            min_elevation=min_elevation,
        )

    # ------------------------------------------------------------------ api

    def meta(self) -> dict[str, Any]:
        summary = self._first_summary
        counts: dict[str, int] = {}
        for item in self._first:
            counts[item.key] = counts.get(item.key, 0) + 1
        payload: dict[str, Any] = {
            "version": __version__,
            "group": summary.get("catalog_group", ""),
            "catalog_size": summary.get("catalog_size", 0),
            "matched": summary.get("military_matches", len(self._first)),
            "classes": sorted(counts),
            "counts": counts,
            "observer": None,
        }
        if self.observer is not None:
            payload["observer"] = {
                "lat": self.observer.lat,
                "lon": self.observer.lon,
                "label": self.observer.label or "observer",
            }
        if summary.get("error"):
            payload["error"] = summary["error"]
        return payload

    def positions(self) -> dict[str, Any]:
        when = datetime.now(timezone.utc)
        findings, summary = sat.snapshot(
            self.catalogue,
            classes=self.classes,
            match=self.match,
            observer=self.observer,
            limit=self.limit,
            overhead=self.overhead,
            min_elevation=self.min_elevation,
            when=when,
        )
        satellites = []
        for item in findings:
            m = item.meta
            satellites.append(
                {
                    "norad": m.get("norad", ""),
                    "name": m.get("name", ""),
                    "class": item.key,
                    "label": m.get("class_label", ""),
                    "programme": m.get("programme", ""),
                    "country": m.get("country") or "",
                    "confidence": m.get("confidence", ""),
                    "lat": m.get("lat", 0.0),
                    "lon": m.get("lon", 0.0),
                    "alt_km": m.get("alt_km", 0.0),
                    "orbit": m.get("orbit", ""),
                    "elevation": m.get("elevation"),
                    "azimuth": m.get("azimuth"),
                    "range_km": m.get("range_km"),
                    "tle_age_hours": m.get("tle_age_hours", 0.0),
                }
            )
        return {
            "generated": when.isoformat(),
            "count": len(satellites),
            "satellites": satellites,
            "summary": {
                "observer": summary.get("observer"),
                "shown": summary.get("shown", len(satellites)),
                "stale_tle_hours": summary.get("stale_tle_hours"),
            },
        }

    def track(self, norad: str) -> dict[str, Any]:
        for item in self.catalogue.detected:
            if item.tle.norad == norad:
                points = sat.ground_track(item.tle, minutes=120.0, step=60.0)
                return {
                    "norad": norad,
                    "name": item.tle.name,
                    "points": [[lat, lon] for lat, lon in points],
                }
        return {}


class _Handler(BaseHTTPRequestHandler):
    """Read-only routes; unknown paths are 404."""

    state: ViewerState
    html: bytes
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        try:
            if parsed.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", self.html)
            elif parsed.path == "/api/meta":
                self._json(self.state.meta())
            elif parsed.path == "/api/positions":
                self._json(self.state.positions())
            elif parsed.path == "/api/track":
                query = parse_qs(parsed.query)
                norad = (query.get("norad") or [""])[0]
                payload = self.state.track(norad)
                self._json(payload, status=200 if payload else 404)
            elif parsed.path == "/data/land.json":
                self._send(200, "application/json; charset=utf-8", read_asset("land.json"))
            elif parsed.path == "/favicon.ico":
                self._send(204, "image/x-icon", b"")
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")
        except Exception as exc:  # noqa: BLE001 - report, never kill the server
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        """Keep the terminal clean: the CLI is the interface, not the server."""


def build_server(
    state: ViewerState,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Create (but do not start) the viewer server."""
    handler = type(
        "ViewerHandler",
        (_Handler,),
        {"state": state, "html": read_asset("viewer.html")},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(
    catalogue: sat.Catalogue,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    observer: sat.Observer | None = None,
    classes: tuple[str, ...] = (),
    match: str = "",
    limit: int = 0,
    overhead: bool = False,
    min_elevation: float = 0.0,
    open_browser: bool = True,
) -> str:
    """Serve the viewer until interrupted and return the URL used."""
    state = ViewerState(
        catalogue,
        observer=observer,
        classes=classes,
        match=match,
        limit=limit,
        overhead=overhead,
        min_elevation=min_elevation,
    )
    server = build_server(state, host=host, port=port)
    bound = server.server_address[1]
    url = f"http://{host}:{bound}/"

    print(f"orbital view: {url}")
    print("local only, read-only. Press Ctrl-C to stop.")

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return url
