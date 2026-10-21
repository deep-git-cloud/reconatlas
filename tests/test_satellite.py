"""Tests for satellite parsing, classification and propagation.

Everything here runs offline: the TLEs are fixed strings and the HTTP
client is a stub, so results are deterministic and no network is touched.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from reconatlas.http import Fetch
from reconatlas.modules import satellite as sat

ISS_TLE = """ISS (ZARYA)
1 25544U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993
2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000"""

GEO_TLE = """TDRS 3
1 19548U 88091B   26293.48881424 -.00000291  00000+0  00000+0 0  9995
2 19548  12.5097 340.1639 0040008 352.1810 183.6218  1.00279973126647"""

# A distinct catalogue number so membership in the military group is
# unambiguous. SGP4 does not validate the checksum, so reusing the ISS
# orbital elements under a different NORAD id is fine for tests.
MH_TLE = """USA 224 (KH-11 14)
1 99999U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993
2 99999  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000"""

CIVILIAN_TLE = """CUBESAT-1
1 25544U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993
2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000"""

WHEN = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------- parsing


def test_parse_three_line_tles() -> None:
    tles = sat.parse_tles(ISS_TLE + "\n" + GEO_TLE)
    assert [t.name for t in tles] == ["ISS (ZARYA)", "TDRS 3"]
    assert tles[0].norad == "25544"
    assert tles[0].epoch == datetime(2026, 10, 20, 13, 7, 22, 548000, tzinfo=timezone.utc)
    assert 50 < tles[0].inclination < 53
    assert tles[0].regime == "LEO"
    assert 400 < tles[0].apogee_km < 450
    assert tles[1].regime == "GEO"


def test_parse_two_line_tles_without_a_name() -> None:
    body = "\n".join(ISS_TLE.splitlines()[1:])
    tles = sat.parse_tles(body)
    assert len(tles) == 1
    assert tles[0].name == "NORAD 25544"


def test_parse_skips_junk() -> None:
    text = "<html>404 not found</html>\n\n" + ISS_TLE + "\nnot a tle\n"
    assert len(sat.parse_tles(text)) == 1
    assert sat.parse_tles("") == []


@pytest.mark.parametrize(
    "raw,expected_year",
    [("26293.5", 2026), ("99293.5", 1999), ("57001.0", 1957), ("56365.0", 2056)],
)
def test_epoch_pivot(raw: str, expected_year: int) -> None:
    parsed = sat._parse_epoch(raw)
    assert parsed is not None
    assert parsed.year == expected_year


def test_bad_epoch_returns_none() -> None:
    assert sat._parse_epoch("") is None
    assert sat._parse_epoch("xxyy") is None


# -------------------------------------------------------------- classification


@pytest.mark.parametrize(
    "name,expected",
    [
        ("USA 224 (KH-11 14)", "recon-optical"),
        ("USA 115 (MILSTAR-1 2)", "comms"),
        ("SBIRS GEO-1 (USA 230)", "early-warning"),
        ("DSP 20 (USA 149)", "early-warning"),
        ("NAVSTAR 43 (USA 132)", "navigation"),
        ("GLONASS-M 758", "navigation"),
        ("BEIDOU-3 M2", "navigation"),
        ("YAOGAN-31 A", "recon"),
        ("SAR-LUPE 2", "recon-radar"),
        ("MENTOR 7 (USA 202)", "sigint"),
        ("TUNDRA 4", "early-warning"),
        ("LOTOS-S 1", "sigint"),
        ("USA 326", "military"),
        ("NROL-82", "recon"),
    ],
)
def test_classification(name: str, expected: str) -> None:
    result = sat.classify(name)
    assert result is not None
    assert result.klass == expected


def test_specific_programme_beats_the_generic_usa_rule() -> None:
    """Regression: "SBIRS GEO-1 (USA 230)" must not be filed as generic US."""
    result = sat.classify("SBIRS GEO-1 (USA 230)")
    assert result is not None
    assert result.klass == "early-warning"
    assert result.programme == "SBIRS"


def test_civilian_names_are_not_flagged() -> None:
    for name in ("ISS (ZARYA)", "STARLINK-1234", "CUBESAT-1", "NOAA 20"):
        assert sat.classify(name) is None


def test_military_group_membership_upgrades_confidence() -> None:
    tles = sat.parse_tles(CIVILIAN_TLE)
    assert sat.detect(tles) == []
    detected = sat.detect(tles, military_norad={"25544"})
    assert len(detected) == 1
    assert detected[0].classification.confidence == "confirmed"
    assert detected[0].classification.klass == "military"


# --------------------------------------------------------------- propagation


def test_iss_position_is_plausible() -> None:
    tle = sat.parse_tles(ISS_TLE)[0]
    pos = sat.position(tle, WHEN)
    assert pos is not None
    assert -52.0 <= pos.lat <= 52.0  # bounded by the 51.6 degree inclination
    assert -180.0 <= pos.lon <= 180.0
    assert 300.0 < pos.alt_km < 600.0


def test_geostationary_longitude_is_stable() -> None:
    tle = sat.parse_tles(GEO_TLE)[0]
    first = sat.position(tle, WHEN)
    later = sat.position(tle, WHEN.replace(hour=14))
    assert first is not None and later is not None
    assert 34_000.0 < first.alt_km < 37_000.0
    assert abs(first.lon - later.lon) < 6.0


def test_observer_directly_under_the_satellite_sees_it_overhead() -> None:
    tle = sat.parse_tles(ISS_TLE)[0]
    sub = sat.position(tle, WHEN)
    assert sub is not None
    observer = sat.Observer(lat=sub.lat, lon=sub.lon, altitude_m=0.0)
    look = sat.position(tle, WHEN, observer=observer)
    assert look is not None
    assert look.elevation is not None and look.elevation > 85.0
    assert look.range_km is not None
    assert abs(look.range_km - sub.alt_km) < 60.0
    assert 0.0 <= look.azimuth <= 360.0


def test_observer_far_away_sees_a_low_elevation() -> None:
    tle = sat.parse_tles(ISS_TLE)[0]
    sub = sat.position(tle, WHEN)
    assert sub is not None
    # Antipodal observer: subtract 180 degrees of longitude.
    lon = (sub.lon + 180.0 + 180.0) % 360.0 - 180.0
    observer = sat.Observer(lat=-sub.lat, lon=lon)
    look = sat.position(tle, WHEN, observer=observer)
    assert look is not None
    assert look.elevation is not None and look.elevation < 0.0


def test_next_passes_for_a_leo_object() -> None:
    tle = sat.parse_tles(ISS_TLE)[0]
    observer = sat.Observer(lat=51.5074, lon=-0.1278)
    passes = sat.next_passes(tle, observer, start=WHEN, hours=24, min_elevation=10, limit=3)
    assert passes, "the ISS should pass over London within a day"
    for item in passes[:1]:
        assert item.max_elevation >= 10.0
        assert 0.0 < item.duration_min < 15.0
        assert item.set_time >= item.rise
    assert len(passes) <= 3


def test_next_passes_honours_the_limit() -> None:
    tle = sat.parse_tles(ISS_TLE)[0]
    observer = sat.Observer(lat=0.0, lon=0.0)
    assert len(sat.next_passes(tle, observer, start=WHEN, hours=48, limit=2)) <= 2


# ------------------------------------------------------------------ collector


class StubHttp:
    """Minimal stand-in for HttpClient that serves fixture catalogues."""

    def __init__(self, groups: dict[str, str], failure: str = "") -> None:
        self.groups = groups
        self.failure = failure
        self.calls: list[str] = []

    def get(self, url: str, params: dict | None = None, **kwargs: object) -> Fetch:
        group = (params or {}).get("GROUP", "")
        assert isinstance(group, str)
        self.calls.append(group)
        if self.failure:
            return Fetch(url=url, status=403, ok=False, text=self.failure)
        body = self.groups.get(group, "")
        return Fetch(url=url, status=200, ok=True, text=body)


@pytest.fixture
def stub() -> StubHttp:
    return StubHttp(
        {
            "active": "\n".join([ISS_TLE, MH_TLE, CIVILIAN_TLE]),
            "military": MH_TLE,
        }
    )


def test_collect_finds_military_and_skips_civilians(stub: StubHttp) -> None:
    findings, summary = sat.collect_satellites(stub, limit=0)
    names = {f.meta["name"] for f in findings}
    assert names == {"USA 224 (KH-11 14)"}
    assert summary["catalog_size"] == 3
    assert summary["military_matches"] == 1
    assert findings[0].meta["confidence"] == "confirmed"


def test_collect_class_filter(stub: StubHttp) -> None:
    findings, _ = sat.collect_satellites(stub, classes=("recon-optical",), limit=0)
    assert len(findings) == 1
    findings, _ = sat.collect_satellites(stub, classes=("navigation",), limit=0)
    assert findings == []


def test_collect_match_filter(stub: StubHttp) -> None:
    findings, _ = sat.collect_satellites(stub, match="KH-11", limit=0)
    assert len(findings) == 1
    findings, _ = sat.collect_satellites(stub, match="nothing-here", limit=0)
    assert findings == []


def test_collect_limit(stub: StubHttp) -> None:
    findings, summary = sat.collect_satellites(stub, limit=1)
    assert len(findings) == 1
    assert summary["shown"] == 1


def test_collect_reports_the_current_subpoint(stub: StubHttp) -> None:
    findings, _ = sat.collect_satellites(stub, limit=0)
    meta = findings[0].meta
    assert -90.0 <= meta["lat"] <= 90.0
    assert -180.0 <= meta["lon"] <= 180.0
    assert meta["alt_km"] > 0
    assert meta["orbit"] in {"LEO", "MEO", "GEO", "HEO"}
    assert meta["tle_epoch"].endswith("Z")


def test_collect_with_observer_and_overhead() -> None:
    stub = StubHttp({"active": MH_TLE, "military": MH_TLE})
    tle = sat.parse_tles(MH_TLE)[0]
    sub = sat.position(tle, datetime.now(timezone.utc))
    assert sub is not None
    observer = sat.Observer(lat=sub.lat, lon=sub.lon)
    findings, summary = sat.collect_satellites(
        stub, observer=observer, overhead=True, limit=0
    )
    assert len(findings) == 1
    assert findings[0].meta["elevation"] > 0
    assert summary["observer"]


def test_collect_predicts_passes() -> None:
    stub = StubHttp({"active": MH_TLE, "military": MH_TLE})
    findings, _ = sat.collect_satellites(
        stub, observer=sat.Observer(lat=51.5, lon=-0.1), passes=2, limit=1
    )
    passes = findings[0].meta["passes"]
    assert isinstance(passes, list)
    assert 0 < len(passes) <= 2
    assert set(passes[0]) >= {"rise", "peak", "set", "max_elevation", "duration_min"}


def test_collect_surfaces_the_celestrak_throttle_message() -> None:
    message = (
        "GP data has not updated since your last successful\r\n"
        "download of GROUP=active at 2026-10-21 09:29:28 UTC."
    )
    findings, summary = sat.collect_satellites(StubHttp({}, failure=message), limit=0)
    assert findings == []
    assert "rate limited" in summary["error"]


def test_throttle_hint_names_the_next_window() -> None:
    body = (
        "GP data has not updated since your last successful\r\n"
        "download of GROUP=active at 2026-10-21 09:29:28 UTC.\r\n"
        "Data is updated once every 2 hours."
    )
    hint = sat._throttle_hint(body)
    assert "11:29Z" in hint
    assert "min" in hint


def test_throttle_hint_without_a_timestamp() -> None:
    assert sat._throttle_hint("something else went wrong") == ""


def test_collect_reports_partial_source_errors() -> None:
    stub = StubHttp({"active": MH_TLE, "military": ""})
    findings, summary = sat.collect_satellites(stub, limit=0)
    assert findings, "the active catalogue still produced a result"
    assert any("military" in err for err in summary["source_errors"])


def test_collect_from_a_local_tle_file(tmp_path) -> None:
    """--tle-file must work with no network access at all."""
    path = tmp_path / "catalogue.tle"
    path.write_text("\n".join([ISS_TLE, MH_TLE, CIVILIAN_TLE]))

    class NoNetwork:
        def get(self, *args: object, **kwargs: object) -> Fetch:
            raise AssertionError("the network must not be touched with --tle-file")

    findings, summary = sat.collect_satellites(NoNetwork(), tle_file=str(path), limit=0)
    assert [f.meta["name"] for f in findings] == ["USA 224 (KH-11 14)"]
    assert summary["catalog_size"] == 3
    assert summary["catalog_group"] == "file:catalogue.tle"


def test_tle_file_without_valid_entries(tmp_path) -> None:
    path = tmp_path / "junk.txt"
    path.write_text("not a tle at all\n")
    findings, summary = sat.collect_satellites(None, tle_file=str(path))
    assert findings == []
    assert "no valid TLEs" in summary["error"]


def test_missing_tle_file(tmp_path) -> None:
    findings, summary = sat.collect_satellites(None, tle_file=str(tmp_path / "absent.tle"))
    assert findings == []
    assert summary["error"]


def test_geojson_shape(stub: StubHttp) -> None:
    findings, _ = sat.collect_satellites(stub, limit=0)
    payload = sat.to_geojson(findings)
    assert payload["type"] == "FeatureCollection"
    feature = payload["features"][0]
    assert feature["geometry"]["type"] == "Point"
    lon, lat = feature["geometry"]["coordinates"]
    assert -180 <= lon <= 180 and -90 <= lat <= 90
    assert feature["properties"]["norad"] == "99999"


def test_render_does_not_crash(stub: StubHttp) -> None:
    from rich.console import Console

    from reconatlas.models import ModuleResult, Report

    findings, summary = sat.collect_satellites(stub, limit=0)
    report = Report(target="test", target_type="satellite")
    report.add(ModuleResult(name="satellite", findings=findings, summary=summary))

    console = Console(record=True, width=120)
    sat.render(report, console=console)
    output = console.export_text()
    assert "KH-11" in output
    assert "Sub-point" in output


def test_formatting_helpers() -> None:
    assert sat.format_lat(51.5) == "51.50°N"
    assert sat.format_lat(-33.86) == "33.86°S"
    assert sat.format_lon(-0.12) == "  0.12°W"
    assert sat.format_lon(151.2) == "151.20°E"


def test_build_renderable_stamps_the_position_time(stub: StubHttp) -> None:
    from rich.console import Console

    from reconatlas.models import ModuleResult

    findings, summary = sat.collect_satellites(stub, limit=0)
    result = ModuleResult(name="satellite", findings=findings, summary=summary)
    console = Console(record=True, width=120)
    console.print(sat.build_renderable(result, WHEN))
    assert "12:00:00Z" in console.export_text()


def test_watch_without_a_terminal_shows_one_snapshot(stub: StubHttp) -> None:
    import io

    from rich.console import Console

    buffer = io.StringIO()
    console = Console(file=buffer, width=120, force_terminal=False)
    sat.watch(stub, interval=1, console=console, limit=0)
    output = buffer.getvalue()
    assert "KH-11" in output
    assert "one snapshot" in output
    # A single snapshot means the catalogue was fetched exactly once.
    assert stub.calls == ["active", "military"]


def test_json_export_is_serialisable(stub: StubHttp) -> None:
    from reconatlas.models import ModuleResult, Report

    findings, summary = sat.collect_satellites(stub, limit=0)
    report = Report(target="test", target_type="satellite")
    report.add(ModuleResult(name="satellite", findings=findings, summary=summary))
    payload = json.loads(report.to_json())
    assert payload["modules"]["satellite"]["findings"][0]["meta"]["norad"] == "99999"
