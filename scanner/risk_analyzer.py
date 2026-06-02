"""
Risk classification engine.

For every open port on every discovered host, the analyzer looks up the port
in the risk_database (loaded from config.yaml) and attaches the associated
risk level, CVSS score, CVE examples, and remediation guidance.

Ports not present in the database receive a default LOW classification.
Results for each host include a computed risk score (0-100) and letter grade.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("NetworkSecurityScanner")

_DEFAULT_FINDING = {
    "level":       "LOW",
    "description": "No specific risk classification for this port. Monitor and restrict with firewall rules.",
    "cvss_score":  0.0,
    "cve_examples": [],
    "remediation": "Apply the principle of least privilege: close the port if it is not required.",
    "service":     "",
}

_RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def analyze_risks(
    scan_results: Dict[str, Any],
    risk_database: Dict[int, Any],
) -> Dict[str, Any]:
    """
    Parameters
    ----------
    scan_results  : Output of port_scanner.run_scan().
    risk_database : Mapping of port (int) → risk attributes from Config.risk_database.

    Returns
    -------
    Dict keyed by host IP; each value contains enriched findings and a risk score.
    """
    enriched: Dict[str, Any] = {}

    for host, host_data in scan_results.items():
        findings: List[Dict[str, Any]] = []

        for proto, ports in host_data.get("protocols", {}).items():
            for port, port_info in ports.items():
                if port_info.get("state") != "open":
                    continue

                db_entry = risk_database.get(int(port), {})

                findings.append({
                    "port":             port,
                    "protocol":         proto,
                    "state":            port_info.get("state"),
                    "service":          port_info.get("service", "unknown"),
                    "product":          port_info.get("product", ""),
                    "version":          port_info.get("version", ""),
                    "extrainfo":        port_info.get("extrainfo", ""),
                    "cpe":              port_info.get("cpe", ""),
                    # Risk attributes from the database (with safe defaults)
                    "risk_level":       db_entry.get("level",       _DEFAULT_FINDING["level"]),
                    "risk_description": db_entry.get("description", _DEFAULT_FINDING["description"]),
                    "cvss_score":       db_entry.get("cvss_score",  _DEFAULT_FINDING["cvss_score"]),
                    "cve_examples":     db_entry.get("cve_examples", []),
                    "remediation":      db_entry.get("remediation", _DEFAULT_FINDING["remediation"]),
                    "known_service":    db_entry.get("service",      ""),
                })

        # Sort: HIGH first, then MEDIUM, then LOW; ties broken by port number
        findings.sort(key=lambda f: (_RISK_ORDER.get(f["risk_level"], 3), f["port"]))

        enriched[host] = {
            "ip":           host_data.get("ip", host),
            "hostname":     host_data.get("hostname", host),
            "state":        host_data.get("state"),
            "os_detection": host_data.get("os_detection", {}),
            "findings":     findings,
            "risk_score":   _compute_score(findings),
        }

        score = enriched[host]["risk_score"]
        logger.info(
            f"Host {host}: {len(findings)} open port(s) | "
            f"HIGH={score['high_findings']} MEDIUM={score['medium_findings']} LOW={score['low_findings']} "
            f"| Score={score['score']}/100 ({score['grade']})"
        )

    return enriched


def _compute_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Weighted risk score (0–100):
      HIGH   → 30 pts each, capped at 60
      MEDIUM → 10 pts each, capped at 20
      LOW    →  2 pts each, capped at 10

    Grade thresholds: CRITICAL ≥ 60, HIGH ≥ 40, MEDIUM ≥ 20, LOW < 20.
    """
    high   = sum(1 for f in findings if f["risk_level"] == "HIGH")
    medium = sum(1 for f in findings if f["risk_level"] == "MEDIUM")
    low    = sum(1 for f in findings if f["risk_level"] == "LOW")

    score = min(high * 30, 60) + min(medium * 10, 20) + min(low * 2, 10)
    score = min(score, 100)

    if score >= 60:
        grade = "CRITICAL"
    elif score >= 40:
        grade = "HIGH"
    elif score >= 20:
        grade = "MEDIUM"
    else:
        grade = "LOW"

    return {
        "score":            score,
        "grade":            grade,
        "high_findings":    high,
        "medium_findings":  medium,
        "low_findings":     low,
    }
