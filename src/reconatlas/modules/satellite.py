"""Military and classified satellite tracking from public orbital data.

Everything here comes from data that is already public. "Detection" is a
classification step over CelesTrak's public GP catalogue: an object is
reported when it appears in CelesTrak's curated military group, or when its
public name matches a known military programme. Each match is propagated
with SGP4 to work out where it is right now.

Sources
-------
CelesTrak GP (TLE)       https://celestrak.org/NORAD/elements/gp.php
    Public, keyless, updated several times a day.
OpenStreetMap Nominatim  https://nominatim.openstreetmap.org/search
    Only used by ``--place`` to turn a place name into coordinates.

Caveats
-------
* A name match is a *heuristic*, not an identification. Confidence is
  reported per object and never upgraded beyond what the source supports.
* Positions are as good as the TLE age. A day-old TLE is fine for "which
  country is this over"; it is not fine for antenna pointing.
* SGP4 needs a real TLE epoch; objects propagated far from epoch drift.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..models import Finding, ModuleResult
from .base import finding

CELESTRAK_GP = "https://celestrak.org/NORAD/elements/gp.php"
NOMINATIM = "https://nominatim.openstreetmap.org/search"

#: WGS-84 ellipsoid, used for every geodetic conversion.
WGS84_A = 6378.137
WGS84_F = 1.0 / 298.257223563
WGS84_E2 = WGS84_F * (2.0 - WGS84_F)

#: A TLE older than this is reported as a warning.
STALE_TLE_HOURS = 72.0

#: CelesTrak refreshes GP data every two hours and refuses repeat downloads
#: of the same group from one address inside that window. Caching for six
#: hours means a normal user refreshes a few times a day and almost never
#: meets the limit. TLEs stay accurate for far longer than that.
TLE_CACHE_TTL = 6 * 60 * 60

#: Class order used for sorting, most interesting first.
CLASS_ORDER = (
    "recon",
    "recon-optical",
    "recon-radar",
    "sigint",
    "early-warning",
    "comms",
    "navigation",
    "weather",
    "military",
    "unknown",
)

CLASS_LABELS = {
    "recon": "reconnaissance",
    "recon-optical": "optical recon",
    "recon-radar": "radar recon",
    "sigint": "signals intelligence",
    "early-warning": "missile warning",
    "comms": "military comms",
    "navigation": "navigation",
    "weather": "military weather",
    "military": "military (unclassified role)",
    "unknown": "unknown",
}

#: (regex, class, programme, country, confidence)
#:
#: Order matters: specific programme names are checked before the generic
#: ``USA nnn`` pattern, so "USA 115 (MILSTAR-1 2)" lands in comms rather
#: than in the catch-all bucket.
PROGRAMME_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    # --- United States: NRO and Space Force
    (r"\bKH-?11\b|\bCRYSTAL\b", "recon-optical", "KH-11 / CRYSTAL", "United States", "confirmed"),
    (r"\bLACROSSE\b|\bONYX\b|\bTOPAZ\b", "recon-radar", "Lacrosse / Onyx", "United States", "confirmed"),
    (r"\bMENTOR\b|\bORION\b", "sigint", "Mentor / Orion", "United States", "confirmed"),
    (r"\bTRUMPET\b|\bMERCURY\b|\bJUMPSEAT\b|\bCHALET\b|\bMAGNUM\b|\bVORTEX\b",
     "sigint", "NRO SIGINT", "United States", "likely"),
    (r"\bMISTY\b", "recon-optical", "Misty", "United States", "likely"),
    (r"\bFIA-?R(ADAR)?\b", "recon-radar", "FIA-Radar", "United States", "likely"),
    (r"\bNOSS\b|\bINTRUDER\b", "sigint", "NOSS / Intruder", "United States", "likely"),
    (r"\bSBIRS\b|\bSTSS\b", "early-warning", "SBIRS", "United States", "confirmed"),
    (r"\bDSP\b", "early-warning", "DSP", "United States", "confirmed"),
    (r"\bAEHF\b|\bMILSTAR\b", "comms", "AEHF / Milstar", "United States", "confirmed"),
    (r"\bWGS\b", "comms", "Wideband Global SATCOM", "United States", "confirmed"),
    (r"\bMUOS\b", "comms", "MUOS", "United States", "confirmed"),
    (r"\bSDS\b", "comms", "Satellite Data System", "United States", "confirmed"),
    (r"\bUFO\b|\bFLTSATCOM\b|\bLEASAT\b", "comms", "UHF follow-on", "United States", "confirmed"),
    (r"\bNAVSTAR\b|\bGPS\b", "navigation", "GPS", "United States", "confirmed"),
    (r"\bDMSP\b", "weather", "DMSP", "United States", "confirmed"),
    # --- Russia
    (r"\bGLONASS\b", "navigation", "GLONASS", "Russia", "confirmed"),
    (r"\bMERIDIAN\b", "comms", "Meridian", "Russia", "confirmed"),
    (r"\bPERSONA\b", "recon-optical", "Persona", "Russia", "likely"),
    (r"\bBARS-?M\b", "recon-optical", "Bars-M", "Russia", "likely"),
    (r"\bLOTOS\b", "sigint", "Lotos-S", "Russia", "likely"),
    (r"\bPION-?NKS\b", "sigint", "Pion-NKS", "Russia", "likely"),
    (r"\bTUNDRA\b|\bEKS\b", "early-warning", "EKS / Tundra", "Russia", "likely"),
    (r"\bRAZDAN\b", "recon-optical", "Razdan", "Russia", "possible"),
    (r"\bPARUS\b|\bTSIKADA\b", "navigation", "Parus / Tsikada", "Russia", "likely"),
    # --- China
    (r"\bYAOGAN\b", "recon", "Yaogan", "China", "likely"),
    (r"\bBEIDOU\b", "navigation", "BeiDou", "China", "confirmed"),
    (r"\bTIANLIAN\b", "comms", "Tianlian data relay", "China", "possible"),
    (r"\bTJS\b", "comms", "TJS", "China", "possible"),
    # --- Europe and others
    (r"\bSAR-?LUPE\b", "recon-radar", "SAR-Lupe", "Germany", "confirmed"),
    (r"\bSARAH\b", "recon-radar", "SARah", "Germany", "confirmed"),
    (r"\bHELIOS\b", "recon-optical", "Helios", "France", "confirmed"),
    (r"\bCSO\b", "recon-optical", "CSO", "France", "confirmed"),
    (r"\bSICRAL\b", "comms", "Sicral", "Italy", "confirmed"),
    (r"\bSYRACUSE\b", "comms", "Syracuse", "France", "confirmed"),
    (r"\bSKYNET\b", "comms", "Skynet", "United Kingdom", "confirmed"),
    (r"\bIGS\b", "recon", "IGS", "Japan", "confirmed"),
    (r"\bOFEQ\b", "recon", "Ofeq", "Israel", "confirmed"),
    (r"\bANASIS\b", "comms", "ANASIS", "South Korea", "confirmed"),
    (r"\bRISAT\b", "recon-radar", "RISAT", "India", "likely"),
    # --- catch-alls
    (r"^USA[- ]?\d+", "military", "US military designation", "United States", "likely"),
    (r"^NROL-", "recon", "NROL (classified)", "United States", "likely"),
)

_COMPILED = tuple(
    (re.compile(pattern), klass, programme, country, confidence)
    for pattern, klass, programme, country, confidence in PROGRAMME_RULES
)

#: Anchored catch-all rules. These only ever run against the full object
#: name and only after every specific programme rule has failed, otherwise
#: "SBIRS GEO-1 (USA 230)" would be filed as a generic US object.
_GENERIC = tuple(rule for rule in _COMPILED if rule[0].pattern.startswith("^"))
_SPECIFIC = tuple(rule for rule in _COMPILED if not rule[0].pattern.startswith("^"))


# --------------------------------------------------------------------- models


@dataclass
class Tle:
    """One parsed two-line element set."""

    name: str
    norad: str
    epoch: datetime
    inclination: float
    eccentricity: float
    period_min: float
    apogee_km: float
    perigee_km: float
    satrec: Any = field(repr=False, compare=False)

    @property
    def mean_motion(self) -> float:
        """Revolutions per day."""
        return 1440.0 / self.period_min if self.period_min else 0.0

    @property
    def regime(self) -> str:
        """Coarse orbit class: LEO, MEO, GEO or HEO."""
        if 1400.0 <= self.period_min <= 1500.0 and self.eccentricity < 0.25:
            return "GEO"
        if self.period_min < 128.0:
            return "LEO"
        if self.period_min < 800.0:
            return "MEO"
        return "HEO"

    @property
    def age_hours(self) -> float:
        delta = datetime.now(timezone.utc) - self.epoch
        return max(0.0, delta.total_seconds() / 3600.0)


@dataclass(frozen=True)
class Classification:
    """Why an object was flagged, and how sure we are."""

    klass: str
    programme: str
    country: str
    confidence: str  # confirmed | likely | possible

    @property
    def label(self) -> str:
        return CLASS_LABELS.get(self.klass, self.klass)


@dataclass(frozen=True)
class Detected:
    """A TLE that the classifier believes is military or state-run."""

    tle: Tle
    classification: Classification


@dataclass(frozen=True)
class Observer:
    """A ground position, in decimal degrees and metres above the ellipsoid."""

    lat: float
    lon: float
    altitude_m: float = 0.0
    label: str = ""


@dataclass(frozen=True)
class Position:
    """Sub-satellite point plus optional look angles from an observer."""

    lat: float
    lon: float
    alt_km: float
    elevation: float | None = None
    azimuth: float | None = None
    range_km: float | None = None

    def subpoint(self) -> str:
        return f"{format_lat(self.lat)} {format_lon(self.lon)}"


@dataclass(frozen=True)
class Pass:
    """One horizon crossing."""

    rise: datetime
    peak: datetime
    set_time: datetime
    max_elevation: float
    in_progress: bool = False
    """True when the object was already above the horizon at the start
    of the search. Common for MEO navigation satellites, which stay up
    for hours."""

    @property
    def duration_min(self) -> float:
        return (self.set_time - self.rise).total_seconds() / 60.0


# ------------------------------------------------------------------ TLE parse


@lru_cache(maxsize=4)
def parse_tles(text: str) -> list[Tle]:
    """Parse a block of three-line or two-line TLEs, skipping broken ones.

    Cached because a full catalogue is ~16k objects and ``--watch`` parses
    the same text every cycle. Callers must treat the result as read-only.
    """
    lines = [line.rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line.strip()]
    out: list[Tle] = []
    i = 0
    while i < len(lines):
        name = ""
        if i + 2 < len(lines) and lines[i + 1].startswith("1 ") and lines[i + 2].startswith("2 "):
            name = lines[i].strip()
            line1, line2 = lines[i + 1], lines[i + 2]
            i += 3
        elif i + 1 < len(lines) and lines[i].startswith("1 ") and lines[i + 1].startswith("2 "):
            line1, line2 = lines[i], lines[i + 1]
            name = f"NORAD {line1[2:7].strip()}"
            i += 2
        else:
            i += 1
            continue

        parsed = _parse_one(name, line1, line2)
        if parsed is not None:
            out.append(parsed)
    return out


def _parse_one(name: str, line1: str, line2: str) -> Tle | None:
    try:
        from sgp4.api import Satrec
    except ModuleNotFoundError:  # pragma: no cover - dependency is declared
        raise RuntimeError(
            "satellite tracking needs the 'sgp4' package: pip install sgp4"
        ) from None

    try:
        satrec = Satrec.twoline2rv(line1, line2)
    except Exception:  # noqa: BLE001 - malformed TLE, skip it
        return None

    epoch = _parse_epoch(line1[18:32])
    if epoch is None:
        return None

    return Tle(
        name=name or f"NORAD {line1[2:7].strip()}",
        norad=line1[2:7].strip(),
        epoch=epoch,
        inclination=math.degrees(satrec.inclo),
        eccentricity=float(satrec.ecco),
        period_min=(2.0 * math.pi / satrec.no) if satrec.no else 0.0,
        apogee_km=float(satrec.alta) * WGS84_A,
        perigee_km=float(satrec.altp) * WGS84_A,
        satrec=satrec,
    )


def _parse_epoch(raw: str) -> datetime | None:
    """Parse the ``YYDDD.DDDDDDDD`` epoch field of TLE line 1."""
    raw = raw.strip()
    if len(raw) < 5:
        return None
    try:
        year = int(raw[:2])
        day = float(raw[2:])
    except ValueError:
        return None
    year += 2000 if year < 57 else 1900
    try:
        return datetime(year, 1, 1, tzinfo=timezone.utc) + timedelta(days=day - 1.0)
    except (ValueError, OverflowError):
        return None


# --------------------------------------------------------------- classifying


def classify(name: str, military_norad: Iterable[str] = ()) -> Classification | None:
    """Return a classification for ``name``, or ``None`` if it is not military.

    A parenthetical programme name is checked first, so
    ``USA 115 (MILSTAR-1 2)`` is classified as comms rather than as the
    generic US military bucket.
    """
    upper = name.upper()
    haystacks: list[str] = []
    paren = re.search(r"\(([^)]*)\)", upper)
    if paren:
        haystacks.append(paren.group(1))
    haystacks.append(upper)

    for hay in haystacks:
        for pattern, klass, programme, country, confidence in _SPECIFIC:
            if pattern.search(hay):
                return Classification(klass, programme, country, confidence)

    for pattern, klass, programme, country, confidence in _GENERIC:
        if pattern.search(upper):
            return Classification(klass, programme, country, confidence)
    return None


def detect(tles: Sequence[Tle], military_norad: Iterable[str] = ()) -> list[Detected]:
    """Flag the objects in ``tles`` that look military or state-run."""
    confirmed = {str(n) for n in military_norad}
    out: list[Detected] = []
    for tle in tles:
        found = classify(tle.name)
        if found is None:
            if tle.norad in confirmed:
                found = Classification(
                    "military", "CelesTrak military group", "", "confirmed"
                )
            else:
                continue
        elif tle.norad in confirmed and found.confidence != "confirmed":
            found = Classification(
                found.klass, found.programme, found.country, "confirmed"
            )
        out.append(Detected(tle=tle, classification=found))
    return out


# ---------------------------------------------------------------- propagation


def _gmst_degrees(jd_ut1: float) -> float:
    """Greenwich mean sidereal time (IAU-82), in degrees."""
    t = (jd_ut1 - 2451545.0) / 36525.0
    seconds = (
        67310.54841
        + (876600.0 * 3600.0 + 8640184.812866) * t
        + 0.093104 * t * t
        - 6.2e-6 * t * t * t
    )
    return (seconds / 240.0) % 360.0


def _jday(when: datetime) -> tuple[float, float]:
    from sgp4.api import jday

    second = when.second + when.microsecond / 1e6
    return jday(when.year, when.month, when.day, when.hour, when.minute, second)


def _ecef_to_geodetic(x: float, y: float, z: float) -> tuple[float, float, float]:
    """Convert an ECEF position (km) to geodetic lat, lon and altitude (km)."""
    lon = math.atan2(y, x)
    p = math.hypot(x, y)
    if p < 1e-9:
        lat = math.copysign(math.pi / 2.0, z)
        return math.degrees(lat), math.degrees(lon), abs(z) - WGS84_A * math.sqrt(1 - WGS84_E2)

    # Bowring's iteration.
    ep2 = WGS84_E2 / (1.0 - WGS84_E2)
    theta = math.atan2(z * WGS84_A, p * WGS84_A * math.sqrt(1.0 - WGS84_E2))
    lat = math.atan2(
        z + ep2 * WGS84_A * math.sqrt(1.0 - WGS84_E2) * math.sin(theta) ** 3,
        p - WGS84_E2 * WGS84_A * math.cos(theta) ** 3,
    )
    sin_lat = math.sin(lat)
    n = WGS84_A / math.sqrt(1.0 - WGS84_E2 * sin_lat * sin_lat)
    alt = p / math.cos(lat) - n
    return math.degrees(lat), math.degrees(lon), alt


def _geodetic_to_ecef(lat_deg: float, lon_deg: float, alt_m: float) -> tuple[float, float, float]:
    lat = math.radians(lat_deg)
    lon = math.radians(lon_deg)
    sin_lat, cos_lat = math.sin(lat), math.cos(lat)
    n = WGS84_A / math.sqrt(1.0 - WGS84_E2 * sin_lat * sin_lat)
    h = alt_m / 1000.0
    x = (n + h) * cos_lat * math.cos(lon)
    y = (n + h) * cos_lat * math.sin(lon)
    z = (n * (1.0 - WGS84_E2) + h) * sin_lat
    return x, y, z


def position(tle: Tle, when: datetime | None = None,
             observer: Observer | None = None) -> Position | None:
    """Propagate ``tle`` to ``when`` and return its geodetic position."""
    when = when or datetime.now(timezone.utc)
    jd, fr = _jday(when)
    try:
        error, r, _ = tle.satrec.sgp4(jd, fr)
    except Exception:  # noqa: BLE001 - sgp4 can raise on pathological TLEs
        return None
    if error != 0:
        return None

    gmst = math.radians(_gmst_degrees(jd + fr))
    cos_g, sin_g = math.cos(gmst), math.sin(gmst)
    x = cos_g * r[0] + sin_g * r[1]
    y = -sin_g * r[0] + cos_g * r[1]
    z = r[2]

    lat, lon, alt = _ecef_to_geodetic(x, y, z)
    if observer is None:
        return Position(lat=lat, lon=lon, alt_km=alt)

    ox, oy, oz = _geodetic_to_ecef(observer.lat, observer.lon, observer.altitude_m)
    dx, dy, dz = x - ox, y - oy, z - oz
    range_km = math.sqrt(dx * dx + dy * dy + dz * dz)

    lat_r = math.radians(observer.lat)
    lon_r = math.radians(observer.lon)
    sin_lat, cos_lat = math.sin(lat_r), math.cos(lat_r)
    sin_lon, cos_lon = math.sin(lon_r), math.cos(lon_r)

    east = -sin_lon * dx + cos_lon * dy
    north = -sin_lat * cos_lon * dx - sin_lat * sin_lon * dy + cos_lat * dz
    up = cos_lat * cos_lon * dx + cos_lat * sin_lon * dy + sin_lat * dz

    elevation = math.degrees(math.asin(max(-1.0, min(1.0, up / range_km))))
    azimuth = math.degrees(math.atan2(east, north)) % 360.0
    return Position(
        lat=lat, lon=lon, alt_km=alt,
        elevation=elevation, azimuth=azimuth, range_km=range_km,
    )


def next_passes(
    tle: Tle,
    observer: Observer,
    *,
    start: datetime | None = None,
    hours: float = 24.0,
    min_elevation: float = 10.0,
    limit: int = 3,
    step_seconds: float = 20.0,
) -> list[Pass]:
    """Find the next ``limit`` passes above ``min_elevation``.

    Sampling is coarse (20 s by default) and the peak is refined to one
    second. Rise and set are accurate to the sampling step.
    """
    if limit <= 0:
        return []
    start = start or datetime.now(timezone.utc)
    end = start + timedelta(hours=hours)
    step = timedelta(seconds=step_seconds)

    passes: list[Pass] = []
    moment = start
    rise: datetime | None = None
    peak_el = -90.0
    peak_at = start
    already_up = False

    while moment <= end and len(passes) < limit:
        pos = position(tle, moment, observer)
        elevation = pos.elevation if pos is not None and pos.elevation is not None else -90.0

        if rise is None:
            if elevation >= min_elevation:
                rise = moment
                already_up = moment == start
                peak_el, peak_at = elevation, moment
        else:
            if elevation > peak_el:
                peak_el, peak_at = elevation, moment
            if elevation < min_elevation:
                passes.append(
                    Pass(
                        rise=rise, peak=peak_at, set_time=moment,
                        max_elevation=peak_el, in_progress=already_up,
                    )
                )
                rise = None
                already_up = False
        moment += step

    if rise is not None and len(passes) < limit:
        passes.append(
            Pass(
                rise=rise, peak=peak_at, set_time=end,
                max_elevation=peak_el, in_progress=already_up,
            )
        )
    return passes


def ground_track(
    tle: Tle,
    *,
    minutes: float = 120.0,
    step: float = 60.0,
    when: datetime | None = None,
) -> list[tuple[float, float]]:
    """Sub-satellite points across a window centred on ``when``.

    Used by the browser viewer to draw where an object has been and is
    going. Longitude is not unwrapped: the caller draws each segment, so
    a track crossing the antimeridian does not shoot across the map.
    """
    centre = when or datetime.now(timezone.utc)
    start = centre - timedelta(minutes=minutes / 2.0)
    count = max(2, int(minutes * 60.0 / step))
    points: list[tuple[float, float]] = []
    for index in range(count + 1):
        pos = position(tle, start + timedelta(seconds=index * step))
        if pos is not None:
            points.append((round(pos.lat, 2), round(pos.lon, 2)))
    return points


# ------------------------------------------------------------- presentation


def format_lat(value: float) -> str:
    return f"{abs(value):5.2f}°{'N' if value >= 0 else 'S'}"


def format_lon(value: float) -> str:
    return f"{abs(value):6.2f}°{'E' if value >= 0 else 'W'}"


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# ------------------------------------------------------------------- network


_THROTTLE_STAMP = re.compile(r"at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC")


def _throttle_hint(text: str) -> str:
    """Turn CelesTrak's refusal into a concrete "try again at" hint.

    The body reads::

        GP data has not updated since your last successful download of
        GROUP=active at 2026-10-21 09:29:28 UTC. Data is updated once
        every 2 hours.
    """
    match = _THROTTLE_STAMP.search(text)
    if not match:
        return ""
    try:
        last = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return ""
    ready = last + timedelta(hours=2)
    minutes = int((ready - datetime.now(timezone.utc)).total_seconds() // 60)
    if minutes <= 0:
        return "the window has expired, retry now"
    return f"next refresh allowed at {ready:%H:%M}Z, in about {minutes} min"


def _fetch_catalog(http: Any, group: str) -> tuple[list[Tle], str, bool]:
    """Fetch one CelesTrak group and parse it.

    Returns ``(tles, error, stale)``. CelesTrak permits one download of a
    group every two hours per address, so the cache lifetime is raised to
    match and an expired copy is preferred over an error.
    """
    fetch = http.get(
        CELESTRAK_GP,
        params={"GROUP": group, "FORMAT": "tle"},
        ttl=TLE_CACHE_TTL,
        allow_stale=True,
    )
    if not fetch.ok and "has not updated since" in fetch.text:
        hint = _throttle_hint(fetch.text)
        detail = "rate limited by source"
        if hint:
            detail += f" ({hint})"
        return [], f"celestrak {group}: {detail}", False
    if not fetch.ok:
        detail = fetch.error or f"HTTP {fetch.status}"
        return [], f"celestrak {group}: {detail}", False
    tles = parse_tles(fetch.text)
    if not tles:
        return [], f"celestrak {group}: no objects in response", False
    return tles, "", fetch.stale


def _load_tle_file(path: str) -> tuple[list[Tle], str]:
    """Read a local two- or three-line TLE file. Returns ``(tles, error)``."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"{path}: {exc}"
    tles = parse_tles(text)
    if not tles:
        return [], f"{path}: no valid TLEs found"
    return tles, ""


def geocode(http: Any, place: str) -> Observer | None:
    """Resolve a place name with OpenStreetMap Nominatim (keyless)."""
    fetch = http.get(
        NOMINATIM,
        params={"q": place, "format": "json", "limit": 1, "addressdetails": 0},
    )
    payload = fetch.json()
    if not isinstance(payload, list) or not payload:
        return None
    hit = payload[0]
    try:
        return Observer(
            lat=float(hit["lat"]),
            lon=float(hit["lon"]),
            label=str(hit.get("display_name", place)),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _class_rank(klass: str) -> int:
    return CLASS_ORDER.index(klass) if klass in CLASS_ORDER else len(CLASS_ORDER)


def _interleave(items: Sequence[Detected]) -> list[Detected]:
    """Round-robin across classes so one constellation cannot dominate.

    Within a class the objects keep catalogue order, which is stable and
    roughly by launch date.
    """
    buckets: dict[str, list[Detected]] = {}
    for item in items:
        buckets.setdefault(item.classification.klass, []).append(item)

    order = sorted(buckets, key=_class_rank)
    out: list[Detected] = []
    while any(buckets[klass] for klass in order):
        for klass in order:
            if buckets[klass]:
                out.append(buckets[klass].pop(0))
    return out


# ------------------------------------------------------------------ collector


@dataclass
class Catalogue:
    """A loaded, classified catalogue that can be re-propagated cheaply."""

    detected: list[Detected] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    stale: bool = False


def load_catalogue(
    http: Any,
    *,
    group: str = "active",
    tle_file: str | None = None,
) -> Catalogue:
    """Fetch (or read) a catalogue and classify it once.

    Detection over the full catalogue costs about half a second, while
    SGP4 over a few hundred objects costs milliseconds. Splitting the two
    lets a live view redraw without reclassifying 16,000 names per frame.
    """
    summary: dict[str, Any] = {"catalog_group": group}
    errors: list[str] = []

    if tle_file:
        catalog, error = _load_tle_file(tle_file)
        catalog_stale = False
        military: list[Tle] = []
        summary["catalog_group"] = f"file:{Path(tle_file).name}"
        if error:
            summary["error"] = error
            return Catalogue(summary=summary, errors=errors)
        # No network signal for the curated group; name heuristics only.
        military_norad: set[str] = set()
    else:
        catalog, error, catalog_stale = _fetch_catalog(http, group)
        if error:
            errors.append(error)

        # The curated military group is small (a few KB) and is the only
        # *explicit* military signal in the catalogue, so always fetch it.
        if group == "military":
            military = catalog
        else:
            military, mil_error, _ = _fetch_catalog(http, "military")
            if mil_error:
                errors.append(mil_error)
        military_norad = {tle.norad for tle in military}

    if not catalog and not military:
        summary["error"] = "; ".join(errors) or "no catalogue data"
        return Catalogue(summary=summary, errors=errors)

    pool = catalog or military
    if not catalog and military:
        # Never let a fallback look like the requested catalogue.
        summary["catalog_group"] = "military (requested group unavailable)"
    if catalog_stale:
        summary["tle_source"] = "stale cache"
    detected = detect(pool, military_norad)
    summary["catalog_size"] = len(pool)
    summary["military_matches"] = len(detected)

    ages = [tle.age_hours for tle in pool[:1]]
    if ages and ages[0] > STALE_TLE_HOURS:
        summary["stale_tle_hours"] = round(ages[0], 1)
    return Catalogue(detected, summary, errors, catalog_stale)


def snapshot(
    catalogue: Catalogue,
    *,
    classes: Sequence[str] = (),
    match: str = "",
    observer: Observer | None = None,
    overhead: bool = False,
    min_elevation: float = 0.0,
    passes: int = 0,
    hours: float = 24.0,
    limit: int = 40,
    when: datetime | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Turn a loaded catalogue into findings for one instant.

    Returns ``(findings, summary)`` so it can be driven by ``safe_collect``.
    """
    summary = dict(catalogue.summary)
    errors = list(catalogue.errors)
    detected = list(catalogue.detected)

    wanted = {c.strip().lower() for c in classes if c.strip()}
    if wanted:
        detected = [d for d in detected if d.classification.klass in wanted]

    if match:
        needle = match.strip().lower()
        detected = [
            d for d in detected
            if needle in d.tle.name.lower() or needle in d.tle.norad
        ]

    # Propagate before filtering on elevation: that filter needs look angles.
    now = when or datetime.now(timezone.utc)
    positions: dict[str, Position] = {}
    for item in detected:
        pos = position(item.tle, now, observer=observer)
        if pos is not None:
            positions[item.tle.norad] = pos

    if overhead:
        threshold = min_elevation if min_elevation > 0 else 0.0
        detected = [
            d for d in detected
            if positions.get(d.tle.norad) is not None
            and (positions[d.tle.norad].elevation or -90.0) >= threshold
        ]

    # With an observer, what matters is what is highest in the sky. Without
    # one, interleave the classes so a single prolific constellation (the
    # Yaogan series alone is ~160 objects) does not fill the whole table.
    if observer is not None:
        detected.sort(
            key=lambda item: -(
                positions[item.tle.norad].elevation
                if item.tle.norad in positions and positions[item.tle.norad].elevation is not None
                else -90.0
            )
        )
    else:
        detected = _interleave(detected)

    if limit > 0:
        detected = detected[:limit]

    counts: dict[str, int] = {}
    for item in detected:
        counts[item.classification.klass] = counts.get(item.classification.klass, 0) + 1

    findings: list[Finding] = []
    for item in detected:
        pos = positions.get(item.tle.norad)
        if pos is None:
            continue
        c = item.classification
        value = f"{item.tle.name}  ·  {pos.subpoint()}  ·  {pos.alt_km:,.0f} km"
        if pos.elevation is not None:
            value += f"  ·  el {pos.elevation:.0f}° az {pos.azimuth:.0f}°"
        note = f"{c.programme} · {c.country or 'unknown operator'} · {c.confidence}"
        findings.append(
            finding(
                "satellite",
                c.klass,
                value,
                source="celestrak TLE / SGP4",
                severity="good" if c.confidence == "confirmed" else "info",
                note=note,
                norad=item.tle.norad,
                name=item.tle.name,
                class_label=c.label,
                programme=c.programme,
                country=c.country,
                confidence=c.confidence,
                lat=round(pos.lat, 4),
                lon=round(pos.lon, 4),
                alt_km=round(pos.alt_km, 1),
                elevation=round(pos.elevation, 1) if pos.elevation is not None else None,
                azimuth=round(pos.azimuth, 1) if pos.azimuth is not None else None,
                range_km=round(pos.range_km, 1) if pos.range_km is not None else None,
                orbit=item.tle.regime,
                inclination=round(item.tle.inclination, 2),
                period_min=round(item.tle.period_min, 1),
                apogee_km=round(item.tle.apogee_km, 1),
                perigee_km=round(item.tle.perigee_km, 1),
                tle_epoch=format_utc(item.tle.epoch),
                tle_age_hours=round(item.tle.age_hours, 1),
            )
        )

    # Pass prediction is expensive, so it runs only on the objects we kept.
    if passes > 0 and observer is not None:
        by_norad = {item.tle.norad: item for item in detected}
        for result in findings:
            item = by_norad.get(str(result.meta.get("norad", "")))
            if item is None:
                continue
            upcoming = next_passes(
                item.tle, observer, hours=hours,
                min_elevation=min_elevation if min_elevation > 0 else 10.0,
                limit=passes,
            )
            result.meta["passes"] = [
                {
                    "rise": format_utc(p.rise),
                    "peak": format_utc(p.peak),
                    "set": format_utc(p.set_time),
                    "max_elevation": round(p.max_elevation, 1),
                    "duration_min": round(p.duration_min, 1),
                    "in_progress": p.in_progress,
                }
                for p in upcoming
            ]

    if errors:
        summary["source_errors"] = errors

    summary["shown"] = len(findings)
    summary["classes"] = ",".join(f"{k}={v}" for k, v in sorted(counts.items()))
    if observer is not None:
        summary["observer"] = f"{observer.lat:.4f},{observer.lon:.4f}"
        if observer.label:
            summary["observer_name"] = observer.label
    return findings, summary


def collect_satellites(
    http: Any,
    *,
    group: str = "active",
    classes: Sequence[str] = (),
    match: str = "",
    observer: Observer | None = None,
    overhead: bool = False,
    min_elevation: float = 0.0,
    passes: int = 0,
    hours: float = 24.0,
    limit: int = 40,
    tle_file: str | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Detect military satellites and report where they are.

    ``tle_file`` reads a local two- or three-line TLE file and skips the
    network entirely, which is the way around CelesTrak's download limit.
    """
    catalogue = load_catalogue(http, group=group, tle_file=tle_file)
    return snapshot(
        catalogue,
        classes=classes,
        match=match,
        observer=observer,
        overhead=overhead,
        min_elevation=min_elevation,
        passes=passes,
        hours=hours,
        limit=limit,
    )


def watch(
    http: Any,
    *,
    interval: float = 5.0,
    console: Any | None = None,
    **kwargs: Any,
) -> None:
    """Redraw live positions until interrupted.

    The catalogue is downloaded once (or read from the cache / a file) and
    every cycle only re-runs SGP4 for the current clock, so watching does
    not consume CelesTrak's download allowance.
    """
    from rich.console import Console
    from rich.live import Live

    console = console or Console()

    try:
        catalogue = load_catalogue(
            http,
            group=kwargs.pop("group", "active"),
            tle_file=kwargs.pop("tle_file", None),
        )
    except Exception as exc:  # noqa: BLE001 - still show why it failed
        catalogue = Catalogue(summary={"error": f"{type(exc).__name__}: {exc}"})

    def frame() -> tuple[ModuleResult, datetime]:
        started = datetime.now(timezone.utc)
        try:
            findings, summary = snapshot(catalogue, when=started, **kwargs)
            errors = [str(err) for err in summary.get("source_errors") or []]
            if summary.get("error"):
                errors.append(str(summary["error"]))
            result = ModuleResult(
                name="satellite", findings=findings, summary=summary, errors=errors
            )
        except Exception as exc:  # noqa: BLE001 - keep the display alive
            result = ModuleResult(
                name="satellite",
                status="error",
                errors=[f"{type(exc).__name__}: {exc}"],
            )
        return result, started

    if not console.is_terminal:
        # Piped output cannot be redrawn, and a killed process would leave
        # nothing behind: show one frame instead of pretending to animate.
        result, started = frame()
        console.print(build_renderable(result, started))
        console.print("[dim]not a terminal: one snapshot shown, --watch ignored.[/dim]")
        return

    try:
        with Live(console=console, auto_refresh=False, transient=False) as live:
            while True:
                result, started = frame()
                live.update(build_renderable(result, started))
                live.refresh()
                time.sleep(max(interval, 1.0))
    except KeyboardInterrupt:
        console.print("\n[dim]stopped[/dim]")


# --------------------------------------------------------------- rendering


def build_renderable(result: ModuleResult, when: datetime | None = None) -> Any:
    """Build the satellite table as a rich renderable.

    Split out from :func:`render` so ``--watch`` can redraw in place
    without stacking a new panel on the terminal every cycle.
    """
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    findings = result.findings
    if not findings:
        parts: list[Any] = [Text(f"error: {err}", style="red") for err in result.errors]
        parts.append(Text("no military satellites matched", style="yellow"))
        return Group(*parts)

    stamp = (when or datetime.now(timezone.utc)).strftime("%H:%M:%SZ")
    parts = [
        Text.assemble(
            ("military satellites  ", "bold white"),
            (f"{len(findings)} shown", "cyan"),
            (f"  ·  {stamp}", "dim"),
        ),
        Text(_summary_line(result.summary), style="dim"),
    ]
    if result.summary.get("tle_source") == "stale cache":
        parts.append(
            Text("using a cached catalogue: the source refused a refresh", style="yellow")
        )
    for err in result.errors:
        parts.append(Text(f"error: {err}", style="red"))
    parts.append(Text(""))

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
        pad_edge=False,
    )
    table.add_column("Class", style="bold cyan", no_wrap=True)
    table.add_column("Object", overflow="fold")
    table.add_column("Sub-point", no_wrap=True)
    table.add_column("Alt", justify="right", no_wrap=True)
    table.add_column("El", justify="right", no_wrap=True)
    table.add_column("Orbit", no_wrap=True)

    for item in findings:
        meta = item.meta
        style = "green" if meta.get("confidence") == "confirmed" else "cyan"
        elevation = meta.get("elevation")
        elevation_text = f"{elevation:.0f}°" if isinstance(elevation, (int, float)) else "-"

        table.add_row(
            Text(item.key, style=style),
            Text.assemble(
                (meta.get("name", ""), "white"),
                (f"  #{meta.get('norad', '')}", "dim"),
            ),
            Text(f"{format_lat(meta.get('lat', 0))} {format_lon(meta.get('lon', 0))}"),
            Text(f"{meta.get('alt_km', 0):,.0f} km"),
            Text(elevation_text, style="yellow" if (elevation or -90) > 0 else "dim"),
            Text(str(meta.get("orbit", "")), style="dim"),
        )
    parts.append(table)

    # Pass predictions, when the caller asked for them.
    slated = [f for f in findings if f.meta.get("passes")]
    if slated:
        parts.append(Text(""))
        parts.append(Text("next passes", style="bold"))
        pass_table = Table(
            show_header=True, header_style="bold magenta", border_style="dim", pad_edge=False
        )
        pass_table.add_column("Object", overflow="fold")
        pass_table.add_column("Rise (UTC)", no_wrap=True)
        pass_table.add_column("Peak", no_wrap=True)
        pass_table.add_column("Max el", justify="right", no_wrap=True)
        pass_table.add_column("Duration", justify="right", no_wrap=True)
        for item in slated:
            for entry in item.meta["passes"]:
                pass_table.add_row(
                    item.meta.get("name", ""),
                    "in progress" if entry.get("in_progress") else entry["rise"],
                    entry["peak"],
                    f"{entry['max_elevation']:.0f}°",
                    f"{entry['duration_min']:.0f} min",
                )
        parts.append(pass_table)

    confirms = sum(1 for f in findings if f.meta.get("confidence") == "confirmed")
    parts.append(Text(""))
    parts.append(
        Text(
            f"{confirms} confirmed by source, {len(findings) - confirms} by name heuristic. "
            "Positions are SGP4 from public TLEs.",
            style="dim",
        )
    )
    return Group(*parts)


def render(report: "Any", console: Any | None = None) -> None:
    """Render a satellite report as a purpose-built table."""
    from rich.console import Console

    console = console or Console()
    result: ModuleResult | None = report.modules.get("satellite")
    if result is None:
        return
    console.print()
    console.print(build_renderable(result))


def _summary_line(summary: dict[str, Any]) -> str:
    parts = []
    if "unavailable" in str(summary.get("catalog_group", "")):
        parts.append("source: military group only (requested catalogue unavailable)")
    if summary.get("catalog_size"):
        parts.append(f"catalog={summary['catalog_size']:,}")
    if summary.get("military_matches") is not None:
        parts.append(f"matched={summary['military_matches']}")
    if summary.get("classes"):
        parts.append(f"classes: {summary['classes']}")
    if summary.get("observer"):
        where = summary.get("observer_name") or summary["observer"]
        parts.append(f"observer={where}")
    if summary.get("stale_tle_hours"):
        parts.append(f"TLE age={summary['stale_tle_hours']:.0f}h")
    return ", ".join(parts)


def to_geojson(findings: Sequence[Finding]) -> dict[str, Any]:
    """Current sub-points as a GeoJSON FeatureCollection for map tools."""
    features = []
    for item in findings:
        meta = item.meta
        lat, lon = meta.get("lat"), meta.get("lon")
        if lat is None or lon is None:
            continue
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": {
                    key: meta.get(key)
                    for key in (
                        "norad", "name", "class_label", "programme", "country",
                        "confidence", "alt_km", "orbit", "inclination", "tle_epoch",
                    )
                },
            }
        )
    return {"type": "FeatureCollection", "features": features}
