"""Tests for the metadata extractor (fully offline)."""

from __future__ import annotations

import zipfile

from reconatlas.modules.exif import collect_metadata


def _write_jpeg(path, exif_tags: dict[int, object]) -> None:
    from PIL import Image

    image = Image.new("RGB", (40, 30), (10, 20, 30))
    exif = image.getexif()
    for tag, value in exif_tags.items():
        exif[tag] = value
    image.save(path, exif=exif)


def test_extracts_basic_exif(tmp_path) -> None:
    path = tmp_path / "photo.jpg"
    _write_jpeg(path, {271: "Canon", 272: "Canon EOS 5D", 315: "Jane Doe"})

    findings, summary = collect_metadata(str(path))

    values = {f.key: f.value for f in findings}
    assert values["Camera make"] == "Canon"
    assert values["Camera model"] == "Canon EOS 5D"
    assert values["Artist"] == "Jane Doe"
    assert summary["format"] == "JPEG"
    assert summary["dimensions"] == "40x30"
    assert summary["sha256"] and summary["md5"]


def test_missing_file_is_reported() -> None:
    findings, summary = collect_metadata("/nonexistent/file.jpg")
    assert findings == []
    assert "error" in summary


def test_pdf_metadata(tmp_path) -> None:
    path = tmp_path / "doc.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Producer (Acme PDF 1.0) /Author (Jane Doe) /CreationDate (D:20240101000000Z) >> endobj\n"
        b"trailer << /Root 1 0 R >>\n"
        b"%PDF-1.4 /URI (https://example.com/report) /JavaScript (app.alert\\(1\\))\n"
    )
    findings, summary = collect_metadata(str(path))

    values = {f.key: f.value for f in findings}
    assert values["PDF Producer"] == "Acme PDF 1.0"
    assert values["PDF Author"] == "Jane Doe"
    assert values["Embedded link"] == "https://example.com/report"
    assert any(f.key == "Embedded JavaScript" for f in findings)
    assert summary["format"] == "PDF"


def test_ooxml_metadata(tmp_path) -> None:
    path = tmp_path / "doc.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "docProps/core.xml",
            '<?xml version="1.0"?><cp:coreProperties '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:creator>Jane Doe</dc:creator>"
            "<cp:lastModifiedBy>John Smith</cp:lastModifiedBy>"
            "</cp:coreProperties>",
        )
    findings, summary = collect_metadata(str(path))

    values = {f.key: f.value for f in findings}
    assert values["Author"] == "Jane Doe"
    assert values["Last modified by"] == "John Smith"
    assert summary["format"] == "DOCX"


def test_unknown_type_falls_back_to_raw_scan(tmp_path) -> None:
    path = tmp_path / "notes.bin"
    path.write_bytes(b"Creator: Some Tool\nAuthor: Someone\n")
    findings, _ = collect_metadata(str(path))
    assert any(f.key == "Creator" for f in findings)
