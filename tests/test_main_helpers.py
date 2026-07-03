"""Tests for CLI helper logic in main.py (format resolution, summary)."""

import main


class _FakeConfig:
    def __init__(self, default_formats):
        self.output = {"default_formats": default_formats}


class TestResolveFormats:
    def test_uses_config_default_when_no_flag(self):
        cfg = _FakeConfig(["json", "html"])
        assert main._resolve_formats(None, cfg) == ["json", "html"]

    def test_both_expands(self):
        cfg = _FakeConfig(["json"])
        assert main._resolve_formats(["both"], cfg) == ["json", "html"]

    def test_all_expands_to_every_format(self):
        cfg = _FakeConfig(["json"])
        assert main._resolve_formats(["all"], cfg) == main.ALL_FORMATS

    def test_dedup_preserves_order(self):
        cfg = _FakeConfig(["json"])
        assert main._resolve_formats(["json", "both", "html"], cfg) == ["json", "html"]


class TestComputeSummary:
    def test_counts_by_level(self, report_data):
        summary = main._compute_summary(report_data["results"])
        assert summary["hosts"] == 1
        assert summary["total_open_ports"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 0


def test_severity_rank_ordering():
    r = main._SEVERITY_RANK
    assert r["none"] < r["low"] < r["medium"] < r["high"] < r["critical"]
