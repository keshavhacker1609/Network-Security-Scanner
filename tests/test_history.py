"""Tests for scan snapshot persistence and diffing."""

from scanner import history


def test_save_and_load_roundtrip(report_data, tmp_path):
    history.save_snapshot(str(tmp_path), report_data)
    loaded = history.load_previous(str(tmp_path), "10.0.0.5")
    assert loaded is not None
    assert loaded["target"] == "10.0.0.5"
    assert "22" in loaded["hosts"]["10.0.0.5"]


def test_load_previous_missing_returns_none(tmp_path):
    assert history.load_previous(str(tmp_path), "203.0.113.9") is None


def test_diff_detects_no_change(report_data, tmp_path):
    history.save_snapshot(str(tmp_path), report_data)
    prev = history.load_previous(str(tmp_path), "10.0.0.5")
    result = history.diff(prev, report_data)
    assert result["has_changes"] is False


def test_diff_detects_opened_port(report_data):
    # Baseline had only port 22; current adds 3306.
    baseline = {
        "scan_id": "old",
        "hosts": {"10.0.0.5": {"22": {"protocol": "tcp", "service": "ssh", "risk_level": "MEDIUM"}}},
    }
    result = history.diff(baseline, report_data)
    assert result["has_changes"] is True
    opened = result["hosts"]["10.0.0.5"]["opened"]
    assert [f["port"] for f in opened] == [3306]


def test_diff_detects_closed_port(report_data):
    baseline = {
        "scan_id": "old",
        "hosts": {"10.0.0.5": {
            "22": {"protocol": "tcp", "service": "ssh", "risk_level": "MEDIUM"},
            "3306": {"protocol": "tcp", "service": "mysql", "risk_level": "HIGH"},
            "8080": {"protocol": "tcp", "service": "http", "risk_level": "MEDIUM"},
        }},
    }
    result = history.diff(baseline, report_data)
    closed = result["hosts"]["10.0.0.5"]["closed"]
    assert [f["port"] for f in closed] == [8080]


def test_safe_key_sanitizes():
    assert history._safe_key("10.0.0.0/24") == "10.0.0.0_24"
    assert history._safe_key("a b:c") == "a_b_c"
