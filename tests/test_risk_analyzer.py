"""Tests for the risk classification and scoring engine."""

from scanner.risk_analyzer import analyze_risks, _compute_score


def test_only_open_ports_included(scan_results, risk_database):
    enriched = analyze_risks(scan_results, risk_database)
    findings = enriched["10.0.0.5"]["findings"]
    ports = {f["port"] for f in findings}
    assert ports == {22, 3306}  # closed 9999 excluded


def test_findings_sorted_high_first(scan_results, risk_database):
    enriched = analyze_risks(scan_results, risk_database)
    levels = [f["risk_level"] for f in enriched["10.0.0.5"]["findings"]]
    assert levels[0] == "HIGH"


def test_unknown_port_gets_low_default(scan_results):
    enriched = analyze_risks(scan_results, {})  # empty DB
    for f in enriched["10.0.0.5"]["findings"]:
        assert f["risk_level"] == "LOW"
        assert f["cvss_score"] == 0.0


def test_risk_enrichment_fields(scan_results, risk_database):
    enriched = analyze_risks(scan_results, risk_database)
    mysql = next(f for f in enriched["10.0.0.5"]["findings"] if f["port"] == 3306)
    assert mysql["cvss_score"] == 9.8
    assert "CVE-2012-2122" in mysql["cve_examples"]
    assert mysql["remediation"]


class TestComputeScore:
    def _f(self, level):
        return {"risk_level": level}

    def test_grades(self):
        assert _compute_score([self._f("HIGH")] * 3)["grade"] == "CRITICAL"
        assert _compute_score([self._f("HIGH")])["grade"] == "MEDIUM"
        assert _compute_score([self._f("LOW")])["grade"] == "LOW"

    def test_score_capped(self):
        result = _compute_score([self._f("HIGH")] * 100)
        assert result["score"] <= 100

    def test_counts(self):
        result = _compute_score([self._f("HIGH"), self._f("MEDIUM"), self._f("LOW")])
        assert result["high_findings"] == 1
        assert result["medium_findings"] == 1
        assert result["low_findings"] == 1
