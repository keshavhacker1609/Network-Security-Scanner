"""
Scan history and differencing.

Each scan can persist a compact snapshot (open ports + risk levels per host)
keyed by target. A later scan of the same target can then be compared against
its most recent snapshot to surface newly-opened and newly-closed ports — the
signal that matters most for continuous monitoring.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("NetworkSecurityScanner")


def _safe_key(target: str) -> str:
    """Filesystem-safe, collision-resistant key for a target string."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target.strip()) or "target"


def _snapshot(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a full report to the minimal state needed for diffing."""
    hosts: Dict[str, Any] = {}
    for host, hd in report_data.get("results", {}).items():
        ports = {}
        for f in hd.get("findings", []):
            ports[str(f["port"])] = {
                "protocol":   f.get("protocol", "tcp"),
                "service":    f.get("service", "unknown"),
                "risk_level": f.get("risk_level", "LOW"),
            }
        hosts[host] = ports
    return {
        "scan_id":   report_data.get("scan_id"),
        "target":    report_data.get("target"),
        "scan_end":  report_data.get("scan_end"),
        "grade":     report_data.get("summary", {}),
        "hosts":     hosts,
    }


def load_previous(history_dir: str, target: str) -> Optional[Dict[str, Any]]:
    """Return the most recent stored snapshot for *target*, or None."""
    path = Path(history_dir) / f"{_safe_key(target)}.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(f"Could not read scan history for '{target}': {exc}")
        return None


def save_snapshot(history_dir: str, report_data: Dict[str, Any]) -> str:
    """Persist the latest snapshot for a target, returning the file path."""
    target = report_data.get("target", "target")
    Path(history_dir).mkdir(parents=True, exist_ok=True)
    path = Path(history_dir) / f"{_safe_key(target)}.json"
    snap = _snapshot(report_data)
    snap["saved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2)
    logger.debug(f"Scan snapshot saved: {path}")
    return str(path)


def diff(previous: Dict[str, Any], report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare the current report against a previous snapshot.

    Returns a dict keyed by host with 'opened' and 'closed' port lists, plus a
    top-level 'has_changes' flag and the reference scan_id/time of the baseline.
    """
    current = _snapshot(report_data)
    prev_hosts = previous.get("hosts", {})
    curr_hosts = current.get("hosts", {})

    per_host: Dict[str, Any] = {}
    any_change = False

    for host in sorted(set(prev_hosts) | set(curr_hosts)):
        before = prev_hosts.get(host, {})
        after = curr_hosts.get(host, {})

        opened = [
            {"port": int(p), **after[p]}
            for p in after if p not in before
        ]
        closed = [
            {"port": int(p), **before[p]}
            for p in before if p not in after
        ]
        opened.sort(key=lambda x: x["port"])
        closed.sort(key=lambda x: x["port"])

        if opened or closed:
            any_change = True
            per_host[host] = {"opened": opened, "closed": closed}

    return {
        "baseline_scan_id": previous.get("scan_id"),
        "baseline_time":    previous.get("saved_at") or previous.get("scan_end"),
        "has_changes":      any_change,
        "hosts":            per_host,
    }


def log_diff(diff_result: Dict[str, Any]) -> None:
    """Emit a human-readable diff summary to the logger."""
    baseline = diff_result.get("baseline_scan_id", "unknown")
    if not diff_result.get("has_changes"):
        logger.info(f"No changes since previous scan (baseline {baseline}).")
        return

    logger.warning(f"Changes detected since previous scan (baseline {baseline}):")
    for host, changes in diff_result["hosts"].items():
        for f in changes["opened"]:
            logger.warning(
                f"  [+] {host}  port {f['port']}/{f['protocol'].upper()} OPENED "
                f"({f['service']}, {f['risk_level']})"
            )
        for f in changes["closed"]:
            logger.info(
                f"  [-] {host}  port {f['port']}/{f['protocol'].upper()} CLOSED "
                f"({f['service']})"
            )
