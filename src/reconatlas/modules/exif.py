"""Metadata extraction from images, PDFs and office documents.

No external services are involved - everything is read from the file
itself, so this module works completely offline.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any

from ..models import Finding
from ..util.text import (
    dms_to_decimal,
    human_bytes,
    md5_file,
    sha256_file,
)
from .base import finding

#: EXIF tag ids we care about, mapped to friendly labels.
EXIF_TAGS = {
    271: "Camera make",
    272: "Camera model",
    306: "Date/time",
    36867: "Date/time original",
    36868: "Date/time digitised",
    37510: "User comment",
    270: "Image description",
    315: "Artist",
    33432: "Copyright",
    305: "Software",
    274: "Orientation",
    282: "X resolution",
    283: "Y resolution",
    296: "Resolution unit",
    34665: "Exif offset",
    34853: "GPS info",
    36864: "Exif version",
    40965: "Interop offset",
    41728: "File source",
    41989: "Focal length",
    41990: "Focal length in 35mm",
    42016: "Image unique id",
    42032: "Camera owner name",
    42033: "Body serial number",
    42036: "Lens make",
    42037: "Lens model",
}

#: GPS tags inside the GPS IFD.
GPS_TAGS = {
    0: "GPS version",
    1: "GPS latitude ref",
    2: "GPS latitude",
    3: "GPS longitude ref",
    4: "GPS longitude",
    5: "GPS altitude ref",
    6: "GPS altitude",
    7: "GPS timestamp",
    18: "GPS map datum",
    29: "GPS date",
}


def _image_findings(path: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    summary: dict[str, Any] = {}

    try:
        from PIL import ExifTags
        from PIL import Image
    except ModuleNotFoundError:
        return findings, {"error": "Pillow is not installed"}

    try:
        image = Image.open(path)
    except Exception as exc:  # noqa: BLE001
        return findings, {"error": f"cannot open image: {exc}"}

    summary["format"] = image.format or "unknown"
    summary["mode"] = image.mode
    summary["dimensions"] = f"{image.width}x{image.height}"
    summary["megapixels"] = round(image.width * image.height / 1_000_000, 2)

    findings.append(
        finding("meta", "Format", f"{summary['format']} ({image.mode})", source="file header")
    )
    findings.append(
        finding("meta", "Dimensions", f"{image.width} x {image.height} px", source="file header")
    )

    exif = None
    try:
        exif = image.getexif()
    except Exception:  # noqa: BLE001
        exif = None

    if exif:
        for tag_id, value in exif.items():
            label = EXIF_TAGS.get(tag_id) or ExifTags.TAGS.get(tag_id, f"Tag {tag_id}")
            if label in ("Exif offset", "GPS info", "Interop offset"):
                continue
            text = _stringify(value)
            if not text:
                continue
            severity = "info"
            if "serial" in label.lower() or "owner" in label.lower():
                severity = "warn"
            findings.append(finding("meta", label, text[:250], source="EXIF", severity=severity))

        # --- GPS
        try:
            gps_ifd = exif.get_ifd(0x8825)  # ExifTags.IFD.GPSInfo
        except Exception:  # noqa: BLE001
            gps_ifd = {}
        if gps_ifd:
            lat = _gps_decimal(gps_ifd, 2, 1)
            lon = _gps_decimal(gps_ifd, 4, 3)
            alt = gps_ifd.get(6)
            if lat is not None and lon is not None:
                findings.append(
                    finding(
                        "meta",
                        "GPS coordinates",
                        f"{lat}, {lon}",
                        source="EXIF",
                        severity="warn",
                        note="Exact camera location recorded in the file.",
                    )
                )
                summary["gps"] = {"lat": lat, "lon": lon}
            if alt is not None:
                try:
                    findings.append(
                        finding("meta", "GPS altitude", f"{float(alt):.1f} m", source="EXIF", severity="warn")
                    )
                except (TypeError, ValueError):
                    pass
            for tag_id, value in gps_ifd.items():
                label = GPS_TAGS.get(tag_id, f"GPS tag {tag_id}")
                text = _stringify(value)
                if text and label not in ("GPS latitude", "GPS longitude"):
                    findings.append(finding("meta", label, text[:120], source="EXIF"))

    # XMP often survives where EXIF is stripped.
    try:
        xmp = image.info.get("xmp") or image.info.get("XML:com.adobe.xmp")
        if xmp:
            findings.append(finding("meta", "XMP metadata", "present", source="file header"))
    except Exception:  # noqa: BLE001
        pass

    return findings, summary


def _gps_decimal(gps_ifd: dict[int, Any], value_id: int, ref_id: int) -> float | None:
    raw = gps_ifd.get(value_id)
    if raw is None:
        return None
    ref = gps_ifd.get(ref_id, "")
    try:
        parts = list(raw)
    except TypeError:
        return None
    if len(parts) < 3:
        return None
    return dms_to_decimal(parts[0], parts[1], parts[2], str(ref))


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            return ""
    text = str(value).strip()
    return "" if text in {"None", "0x", "b''"} else text


def _pdf_findings(path: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    summary: dict[str, Any] = {"format": "PDF"}

    try:
        data = path.read_bytes()
    except OSError as exc:
        return findings, {"error": str(exc)}

    # The document info dictionary is usually plain-text in the file.
    for match in re.finditer(
        rb"/(Author|Creator|Producer|Title|Subject|Keywords|CreationDate|ModDate)\s*\(([^)]{0,300})\)",
        data,
    ):
        key = match.group(1).decode("ascii", "ignore")
        value = match.group(2).decode("utf-8", "ignore").strip()
        if value:
            findings.append(finding("meta", f"PDF {key}", value[:250], source="PDF info dict"))

    for match in re.finditer(rb"/(CreationDate|ModDate)\s*\(([^)]{0,64})\)", data):
        key = match.group(1).decode("ascii", "ignore")
        value = match.group(2).decode("utf-8", "ignore").strip()
        if value:
            findings.append(finding("meta", f"PDF {key}", value, source="PDF info dict"))

    # PDF /URI annotations reveal embedded links.
    uris = re.findall(rb"/URI\s*\(([^)]{1,400})\)", data)
    seen: set[str] = set()
    for uri in uris[:40]:
        value = uri.decode("utf-8", "ignore").strip()
        if value and value not in seen:
            seen.add(value)
            findings.append(finding("meta", "Embedded link", value, source="PDF annotations"))
    summary["embedded_links"] = len(seen)

    # JavaScript in a PDF is a red flag worth surfacing.
    if b"/JavaScript" in data or b"/JS" in data:
        findings.append(
            finding("meta", "Embedded JavaScript", "present", source="PDF structure", severity="warn")
        )

    pages = len(re.findall(rb"/Type\s*/Page[^s]", data))
    if pages:
        summary["pages"] = pages
        findings.append(finding("meta", "Pages", str(pages), source="PDF structure"))

    return findings, summary


def _office_findings(path: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    summary: dict[str, Any] = {"format": path.suffix.lstrip(".").upper()}

    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            for candidate in ("docProps/core.xml", "docProps/app.xml"):
                if candidate not in names:
                    continue
                xml = archive.read(candidate).decode("utf-8", "ignore")
                for match in re.finditer(
                    r"<(dc|cp|dcterms):([A-Za-z]+)[^>]*>([^<]{0,300})</", xml
                ):
                    prefix, key, value = match.groups()
                    value = value.strip()
                    if not value:
                        continue
                    label = {
                        "creator": "Author",
                        "title": "Title",
                        "subject": "Subject",
                        "description": "Description",
                        "keywords": "Keywords",
                        "lastModifiedBy": "Last modified by",
                        "revision": "Revision",
                        "created": "Created",
                        "modified": "Modified",
                        "Application": "Application",
                        "Company": "Company",
                        "Template": "Template",
                        "TotalTime": "Editing time",
                    }.get(key, f"{prefix}:{key}")
                    severity = "warn" if label in {"Last modified by", "Author"} else "info"
                    findings.append(
                        finding("meta", label, value[:250], source="document properties", severity=severity)
                    )
            summary["entries"] = len(names)
    except zipfile.BadZipFile:
        return findings, {"error": "not a valid OOXML container"}
    except OSError as exc:
        return findings, {"error": str(exc)}

    return findings, summary


def collect_metadata(path_str: str) -> tuple[list[Finding], dict[str, Any]]:
    """Extract metadata from an image, PDF or office document."""
    path = Path(path_str)
    if not path.exists():
        return [], {"error": "file not found"}
    if not path.is_file():
        return [], {"error": "not a regular file"}

    findings: list[Finding] = []
    summary: dict[str, Any] = {
        "file": str(path),
        "size": human_bytes(path.stat().st_size),
    }

    try:
        summary["sha256"] = sha256_file(str(path))
        summary["md5"] = md5_file(str(path))
    except OSError:
        pass

    suffix = path.suffix.lower()
    if suffix in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".gif", ".bmp", ".heic"}:
        image_findings, image_summary = _image_findings(path)
        findings.extend(image_findings)
        summary.update(image_summary)
    elif suffix == ".pdf":
        pdf_findings, pdf_summary = _pdf_findings(path)
        findings.extend(pdf_findings)
        summary.update(pdf_summary)
    elif suffix in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}:
        office_findings, office_summary = _office_findings(path)
        findings.extend(office_findings)
        summary.update(office_summary)
    else:
        # Fall back to generic strings for unknown types.
        try:
            data = path.read_bytes()
        except OSError as exc:
            return findings, {**summary, "error": str(exc)}
        for match in re.finditer(
            rb"(?:Author|Creator|Producer|Company|Title)\s*[=:]\s*([^\r\n\x00]{1,120})", data
        ):
            key = match.group(0).split(b":")[0].split(b"=")[0].decode("ascii", "ignore")
            value = match.group(1).decode("utf-8", "ignore").strip()
            if value:
                findings.append(finding("meta", key, value[:200], source="raw file scan"))
        summary["format"] = suffix.lstrip(".").upper() or "unknown"

    summary["finding_count"] = len(findings)
    return findings, summary
