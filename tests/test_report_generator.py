"""Tests for the multi-format report renderers."""

import json

from scanner.report_generator import (
    generate_reports,
    _render_html,
    _render_csv,
    _render_markdown,
    _render_sarif,
)


def test_html_contains_target_and_findings(report_data):
    html = _render_html(report_data, "10.0.0.5")
    assert "<html" in html
    assert "10.0.0.5" in html
    assert "mysql" in html


def test_csv_has_header_and_rows(report_data):
    csv_text = _render_csv(report_data)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("host,hostname,port")
    assert len(lines) == 3  # header + 2 open ports


def test_markdown_structure(report_data):
    md = _render_markdown(report_data, "10.0.0.5")
    assert md.startswith("# Network Security Scan Report")
    assert "## Summary" in md
    assert "| Port |" in md


def test_sarif_is_valid_json_and_schema(report_data):
    sarif = json.loads(_render_sarif(report_data))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Network Security Scanner"
    assert len(run["results"]) == 2
    # HIGH finding maps to SARIF 'error'
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels


def test_generate_all_formats(report_data, tmp_path):
    formats = ["json", "html", "csv", "markdown", "sarif"]
    paths = generate_reports(report_data, str(tmp_path), "scan1", "10.0.0.5", formats)
    assert set(paths) == set(formats)
    for path in paths.values():
        assert path  # file path returned
        with open(path, encoding="utf-8") as fh:
            assert fh.read().strip()  # non-empty


def test_unknown_format_skipped(report_data, tmp_path):
    paths = generate_reports(report_data, str(tmp_path), "scan1", "10.0.0.5", ["json", "bogus"])
    assert "json" in paths
    assert "bogus" not in paths
