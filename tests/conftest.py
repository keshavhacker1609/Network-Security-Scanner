"""Shared fixtures for the test suite."""

import pytest


@pytest.fixture
def scan_results():
    """Raw per-host scan output as produced by port_scanner.run_scan()."""
    return {
        "10.0.0.5": {
            "ip": "10.0.0.5",
            "hostname": "db.internal",
            "state": "up",
            "os_detection": {"guessed": "Linux 5.x", "matches": []},
            "protocols": {
                "tcp": {
                    22: {"state": "open", "service": "ssh", "product": "OpenSSH",
                         "version": "8.9", "extrainfo": "", "cpe": "", "reason": "syn-ack",
                         "script_output": {}},
                    3306: {"state": "open", "service": "mysql", "product": "MySQL",
                           "version": "8.0", "extrainfo": "", "cpe": "", "reason": "syn-ack",
                           "script_output": {}},
                    9999: {"state": "closed", "service": "unknown", "product": "",
                           "version": "", "extrainfo": "", "cpe": "", "reason": "reset",
                           "script_output": {}},
                }
            },
        }
    }


@pytest.fixture
def risk_database():
    return {
        22: {"service": "SSH", "level": "MEDIUM", "description": "SSH exposed.",
             "cvss_score": 5.3, "cve_examples": ["CVE-2023-38408"],
             "remediation": "Restrict by IP."},
        3306: {"service": "MySQL", "level": "HIGH", "description": "DB exposed.",
               "cvss_score": 9.8, "cve_examples": ["CVE-2012-2122"],
               "remediation": "Bind to localhost."},
    }


@pytest.fixture
def report_data(scan_results, risk_database):
    """A fully analyzed report payload, built through the real analyzer."""
    from scanner.risk_analyzer import analyze_risks
    enriched = analyze_risks(scan_results, risk_database)
    summary = {"hosts": 1, "total_open_ports": 2, "high": 1, "medium": 1, "low": 0}
    return {
        "scan_id": "20260704_120000",
        "scanner_version": "2.1.0",
        "target": "10.0.0.5",
        "scan_type": "standard",
        "nmap_arguments": "-sV --top-ports 1000 -T4",
        "port_spec": "profile default",
        "scan_start": "2026-07-04 12:00:00",
        "scan_end": "2026-07-04 12:00:03",
        "scan_duration_seconds": 3.0,
        "hosts_discovered": 1,
        "results": enriched,
        "summary": summary,
    }
