"""Text helpers: GPS conversion, hashing, duration and size formatting."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def md5_file(path: str, chunk: int = 1 << 20) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def gravatar_hash(email: str) -> str:
    """The MD5 hash Gravatar uses to key profile images."""
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def dms_to_decimal(degrees: float, minutes: float, seconds: float, ref: str) -> float | None:
    """Convert a GPS degree/minute/second triple plus hemisphere to decimal."""
    if degrees is None:
        return None
    try:
        value = float(degrees) + float(minutes or 0) / 60.0 + float(seconds or 0) / 3600.0
    except (TypeError, ValueError):
        return None
    ref = (ref or "").strip().upper()
    if ref in {"S", "W"}:
        value = -value
    return round(value, 6)


def meters_to_degrees(value: float, axis: str) -> float | None:
    """Convert a GPS reference to decimal degrees."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    if axis == "lat":
        return round(value / 111_320.0, 6)
    if axis == "lon":
        return round(value / (111_320.0 * math.cos(math.radians(value or 0))), 6)
    return None


def human_bytes(size: int) -> str:
    step = 1024.0
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < step:
            return f"{value:.1f}{unit}"
        value /= step
    return f"{value:.1f}PB"


def human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def parse_ts(value: Any) -> str:
    """Normalise assorted timestamp encodings into an ISO-8601 UTC string."""
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e12:  # milliseconds
            seconds /= 1000.0
        try:
            return (
                datetime.fromtimestamp(seconds, tz=timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
        except (OverflowError, OSError, ValueError):
            return str(value)
    text = str(value).strip()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            continue
    return text


def safe_json(obj: Any) -> str:
    """Compact, stable JSON for logging and note fields."""
    return json.dumps(obj, sort_keys=True, default=str)
