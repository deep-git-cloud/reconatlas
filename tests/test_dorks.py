"""Tests for the dork generator (fully offline)."""

from __future__ import annotations

from reconatlas.modules.dorks import build_dorks, collect_dorks


def test_target_is_reduced_to_a_host() -> None:
    dorks = build_dorks("https://www.example.com/some/path", global_scope=False)
    assert dorks
    for _label, query in dorks:
        assert "site:example.com" in query
        assert "https://" not in query
        assert "www.example.com" not in query


def test_site_scoped_queries_only() -> None:
    dorks = build_dorks("example.com", global_scope=False)
    assert all("site:example.com" in query for _label, query in dorks)


def test_global_queries_added() -> None:
    scoped = build_dorks("example.com", global_scope=False)
    glob = build_dorks("example.com", global_scope=True)
    assert len(glob) > len(scoped)
    # The extra queries are not restricted to the target site.
    assert any("site:example.com" not in query for _label, query in glob[len(scoped) :])


def test_collect_returns_findings_with_search_urls() -> None:
    findings, summary = collect_dorks("example.com")
    assert len(findings) == summary["dorks"]
    assert findings[0].meta["search_url"].startswith("https://www.google.com/search?q=")
    assert all(f.value for f in findings)
