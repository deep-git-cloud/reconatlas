"""Tests for the local browser view.

The server is started on an ephemeral loopback port for the duration of a
test; nothing here contacts the internet.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from reconatlas import viewer
from reconatlas.modules import satellite as sat

KH11 = """USA 224 (KH-11 14)
1 99999U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993
2 99999  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000"""

LACROSSE = """USA 215 (LACROSSE 5)
1 90000U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993
2 90000  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000"""


def _catalogue() -> sat.Catalogue:
    tles = sat.parse_tles(KH11 + "\n" + LACROSSE)
    detected = sat.detect(tles)
    return sat.Catalogue(
        detected=detected,
        summary={
            "catalog_group": "test",
            "catalog_size": len(tles),
            "military_matches": len(detected),
        },
        errors=[],
    )


def _serve(state: viewer.ViewerState):
    server = viewer.build_server(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def test_meta_describes_the_catalogue() -> None:
    state = viewer.ViewerState(
        _catalogue(), observer=sat.Observer(lat=51.5, lon=-0.1, label="London")
    )
    meta = state.meta()
    assert meta["matched"] == 2
    assert meta["catalog_size"] == 2
    assert meta["classes"] == ["recon-optical", "recon-radar"]
    assert meta["observer"] == {"lat": 51.5, "lon": -0.1, "label": "London"}


def test_positions_carry_what_the_map_draws() -> None:
    payload = viewer.ViewerState(_catalogue()).positions()
    assert payload["count"] == 2
    first = payload["satellites"][0]
    for key in (
        "norad", "name", "class", "lat", "lon", "alt_km",
        "elevation", "confidence", "orbit",
    ):
        assert key in first
    assert -90 <= first["lat"] <= 90
    assert -180 <= first["lon"] <= 180
    assert payload["generated"].endswith("+00:00")


def test_positions_use_the_observer_for_look_angles() -> None:
    state = viewer.ViewerState(_catalogue(), observer=sat.Observer(lat=51.5, lon=-0.1))
    payload = state.positions()
    assert all(site["elevation"] is not None for site in payload["satellites"])


def test_track_returns_a_path_for_a_known_object() -> None:
    state = viewer.ViewerState(_catalogue())
    track = state.track("99999")
    assert track["norad"] == "99999"
    assert len(track["points"]) > 100
    assert all(len(point) == 2 for point in track["points"])


def test_track_unknown_object_is_empty() -> None:
    assert viewer.ViewerState(_catalogue()).track("1") == {}


def test_http_routes() -> None:
    server, thread, base = _serve(viewer.ViewerState(_catalogue()))
    try:
        with urllib.request.urlopen(base + "/") as response:
            page = response.read().decode()
            assert response.status == 200
            assert "orbital view" in page

        with urllib.request.urlopen(base + "/api/meta") as response:
            meta = json.load(response)
            assert meta["matched"] == 2

        with urllib.request.urlopen(base + "/api/positions") as response:
            payload = json.load(response)
            assert payload["count"] == 2

        with urllib.request.urlopen(base + "/data/land.json") as response:
            land = json.load(response)
            assert land["rings"]

        try:
            urllib.request.urlopen(base + "/missing")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:  # pragma: no cover - the server must not serve unknown paths
            raise AssertionError("expected a 404")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_bundled_assets_are_present() -> None:
    assert b"orbital view" in viewer.read_asset("viewer.html")
    assert b"rings" in viewer.read_asset("land.json")
