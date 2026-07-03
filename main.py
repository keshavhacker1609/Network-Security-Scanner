#!/usr/bin/env python3
"""
Network Security Scanner (NSS) v2.0.0
Automated TCP/IP reconnaissance, service detection, and risk classification.

Usage examples:
  python main.py --target 192.168.1.1
  python main.py --target 192.168.1.0/24 --ports 1-1024 --scan-type aggressive
  python main.py --target example.com --ports 80,443,8080 --format json
  python main.py --target 10.0.0.1 --scan-type stealth --output-dir /tmp/reports
"""

import sys
import argparse
from datetime import datetime
from pathlib import Path

# Ensure project root is always importable regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from config.logger import setup_logger
from scanner.validator import validate_target, validate_ports
from scanner.port_scanner import run_scan, SCAN_PROFILES
from scanner.risk_analyzer import analyze_risks
from scanner.report_generator import generate_reports
from scanner import history as scan_history


VERSION = "2.1.0"

ALL_FORMATS = ["json", "html", "csv", "markdown", "sarif"]

# Severity ranking used by --fail-on gating (higher = worse).
_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _resolve_formats(cli_format, config) -> list:
    """Expand the (possibly repeated) --format flag, honouring config defaults."""
    if not cli_format:
        chosen = config.output.get("default_formats", ["json", "html"])
    else:
        chosen = cli_format

    resolved: list = []
    for fmt in chosen:
        if fmt == "all":
            resolved.extend(ALL_FORMATS)
        elif fmt == "both":
            resolved.extend(["json", "html"])
        else:
            resolved.append(fmt)

    # De-duplicate while preserving order.
    seen = set()
    return [f for f in resolved if not (f in seen or seen.add(f))]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nss",
        description="Network Security Scanner — automated recon, service detection, and risk classification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
scan types:
  quick       Top 100 ports, fast (-T4)
  standard    Top 1000 ports + service versions (default)
  aggressive  Top 1000 ports + scripts + OS detection (-O)
  stealth     Top 1000 ports, slow SYN scan (-T2)

exit codes:
  0  Clean — no findings at or above the --fail-on threshold
  1  Error — scan or config failure
  2  Gate  — a finding at or above the --fail-on threshold was found
  130 Interrupted (Ctrl-C)
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="TARGET",
        help="IPv4/IPv6 address, hostname, or CIDR range (e.g. 192.168.1.0/24).",
    )

    port_group = parser.add_argument_group("port options")
    port_group.add_argument(
        "--ports", "-p",
        metavar="PORTS",
        default=None,
        help="Port spec: 80 | 1-1024 | 80,443,8080 | all.  Overrides --scan-type top-ports default.",
    )
    port_group.add_argument(
        "--scan-type", "-s",
        choices=list(SCAN_PROFILES),
        default="standard",
        metavar="TYPE",
        help=f"Scan profile: {', '.join(SCAN_PROFILES)} (default: standard).",
    )

    out_group = parser.add_argument_group("output options")
    out_group.add_argument(
        "--output-dir", "-o",
        metavar="DIR",
        default=None,
        help="Directory for reports (overrides config value).",
    )
    out_group.add_argument(
        "--format", "-f",
        choices=["json", "html", "csv", "markdown", "sarif", "both", "all"],
        action="append",
        default=None,
        help="Report format. 'both' = json+html, 'all' = every format. "
             "Repeat to combine (e.g. -f json -f sarif). Default: config's output.default_formats.",
    )
    out_group.add_argument(
        "--no-report",
        action="store_true",
        help="Skip writing report files; print summary to console only.",
    )

    monitor_group = parser.add_argument_group("monitoring options")
    monitor_group.add_argument(
        "--diff",
        action="store_true",
        help="Compare this scan against the previous scan of the same target and report changes.",
    )
    monitor_group.add_argument(
        "--no-history",
        action="store_true",
        help="Do not persist a scan snapshot for later diffing.",
    )
    monitor_group.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default=None,
        metavar="LEVEL",
        help="Exit non-zero (code 2) when a finding at or above LEVEL is present. "
             "Overrides config's ci.fail_on.",
    )

    misc_group = parser.add_argument_group("miscellaneous")
    misc_group.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        default=None,
        help="Hard scan timeout in seconds (overrides config value).",
    )
    misc_group.add_argument(
        "--config", "-c",
        metavar="PATH",
        default=None,
        help="Path to a custom config.yaml.",
    )
    misc_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    misc_group.add_argument(
        "--version",
        action="version",
        version=f"Network Security Scanner v{VERSION}",
    )

    return parser


def _compute_summary(risk_results: dict) -> dict:
    summary = {"hosts": len(risk_results), "total_open_ports": 0, "high": 0, "medium": 0, "low": 0}
    for host_data in risk_results.values():
        for finding in host_data.get("findings", []):
            summary["total_open_ports"] += 1
            level = finding.get("risk_level", "LOW").upper()
            if level == "HIGH":
                summary["high"] += 1
            elif level == "MEDIUM":
                summary["medium"] += 1
            else:
                summary["low"] += 1
    return summary


def _print_console_summary(report_data: dict, logger) -> None:
    s = report_data["summary"]
    sep = "─" * 56
    logger.info(sep)
    logger.info("SCAN SUMMARY")
    logger.info(f"  Target          : {report_data['target']}")
    logger.info(f"  Hosts found     : {s['hosts']}")
    logger.info(f"  Open ports      : {s['total_open_ports']}")
    logger.info(f"  HIGH risk       : {s['high']}")
    logger.info(f"  MEDIUM risk     : {s['medium']}")
    logger.info(f"  LOW risk        : {s['low']}")
    logger.info(f"  Duration        : {report_data['scan_duration_seconds']} s")
    logger.info(sep)

    for host, hd in report_data.get("results", {}).items():
        score = hd.get("risk_score", {})
        logger.info(
            f"  {host:20s}  score={score.get('score', 0):3d}/100  grade={score.get('grade', 'LOW')}"
        )
        for f in hd.get("findings", []):
            level = f["risk_level"]
            prefix = "  [!]" if level == "HIGH" else "  [~]" if level == "MEDIUM" else "  [ ]"
            ver = f"{f['product']} {f['version']}".strip()
            svc = f"{f['service']}" + (f" ({ver})" if ver else "")
            logger.info(f"      {prefix} {f['port']:5}/{f['protocol'].upper():3}  {level:6}  {svc}")

    logger.info(sep)


def main() -> int:
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Load configuration ────────────────────────────────────
    try:
        config = Config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # ── Setup logger ──────────────────────────────────────────
    log_level  = "DEBUG" if args.verbose else config.logging_config.get("level", "INFO")
    log_file   = config.logging_config.get("file", "logs/scanner.log")
    max_bytes  = config.logging_config.get("max_bytes", 10_485_760)
    bkp_count  = config.logging_config.get("backup_count", 5)
    logger     = setup_logger(log_level, log_file, max_bytes, bkp_count)

    logger.info("=" * 56)
    logger.info(f"Network Security Scanner v{VERSION}")
    logger.info("=" * 56)

    # ── Validate target ───────────────────────────────────────
    valid, msg = validate_target(args.target)
    if not valid:
        logger.error(f"Invalid target — {msg}")
        return 1
    logger.info(f"Target  : {args.target}  [{msg}]")

    # ── Validate / normalise port spec ────────────────────────
    ports: str | None = None
    if args.ports:
        valid_p, port_msg = validate_ports(args.ports)
        if not valid_p:
            logger.error(f"Invalid port specification — {port_msg}")
            return 1
        ports = port_msg
        logger.info(f"Ports   : {ports}")
    else:
        logger.info("Ports   : profile default (top-ports)")

    # ── Resolve runtime settings ──────────────────────────────
    timeout    = args.timeout or config.scanner.get("timeout", 300)
    output_dir = args.output_dir or config.output.get("reports_dir", "reports")
    formats    = _resolve_formats(args.format, config)

    scan_id         = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_start      = datetime.now()
    start_timestamp = scan_start.strftime("%Y-%m-%d %H:%M:%S")

    logger.info(f"Scan ID : {scan_id}")
    logger.info(f"Profile : {args.scan_type}")
    logger.info(f"Timeout : {timeout} s")
    logger.info(f"Started : {start_timestamp}")

    # ── Run port scan ─────────────────────────────────────────
    try:
        scan_results = run_scan(
            target=args.target,
            ports=ports,
            scan_profile=args.scan_type,
            timeout=timeout,
        )
    except RuntimeError as exc:
        logger.error(str(exc))
        return 1
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user (Ctrl-C).")
        return 130

    scan_end       = datetime.now()
    duration       = round((scan_end - scan_start).total_seconds(), 2)
    end_timestamp  = scan_end.strftime("%Y-%m-%d %H:%M:%S")

    logger.info(f"Scan complete — {len(scan_results)} host(s) discovered in {duration} s.")

    # ── Risk analysis ─────────────────────────────────────────
    logger.info("Running risk analysis...")
    risk_results = analyze_risks(scan_results, config.risk_database)

    # ── Assemble report payload ───────────────────────────────
    report_data = {
        "scan_id":               scan_id,
        "scanner_version":       VERSION,
        "target":                args.target,
        "scan_type":             args.scan_type,
        "nmap_arguments":        None,        # filled below
        "port_spec":             ports or "profile default",
        "scan_start":            start_timestamp,
        "scan_end":              end_timestamp,
        "scan_duration_seconds": duration,
        "hosts_discovered":      len(scan_results),
        "results":               risk_results,
        "summary":               _compute_summary(risk_results),
    }

    # Pull actual nmap args from the profile for transparency
    from scanner.port_scanner import SCAN_PROFILES as _P
    report_data["nmap_arguments"] = _P.get(args.scan_type, "")

    # ── Console summary ───────────────────────────────────────
    _print_console_summary(report_data, logger)

    # ── History & diff ────────────────────────────────────────
    hist_cfg     = config.history
    hist_enabled = hist_cfg.get("enabled", True)
    hist_dir     = hist_cfg.get("dir", "logs/history")

    if args.diff and hist_enabled:
        previous = scan_history.load_previous(hist_dir, args.target)
        if previous is None:
            logger.info("No previous scan on record for this target — nothing to diff.")
        else:
            diff_result = scan_history.diff(previous, report_data)
            report_data["diff"] = diff_result
            scan_history.log_diff(diff_result)

    if hist_enabled and not args.no_history:
        try:
            scan_history.save_snapshot(hist_dir, report_data)
        except OSError as exc:
            logger.warning(f"Could not save scan snapshot: {exc}")

    # ── Write reports ─────────────────────────────────────────
    if not args.no_report:
        try:
            paths = generate_reports(
                data=report_data,
                output_dir=output_dir,
                scan_id=scan_id,
                target=args.target,
                formats=formats,
            )
            for fmt, path in paths.items():
                logger.info(f"{fmt.upper()} report : {path}")
        except OSError as exc:
            logger.error(f"Failed to write reports: {exc}")
            return 1

    # ── Exit code reflects overall risk (CI gating) ──────────
    fail_on = (args.fail_on or config.ci.get("fail_on", "high")).lower()
    threshold = _SEVERITY_RANK.get(fail_on, 3)
    summary = report_data["summary"]

    # Highest severity actually observed in this scan.
    if summary["high"]:
        observed = _SEVERITY_RANK["high"]
        observed_label = "HIGH"
    elif summary["medium"]:
        observed = _SEVERITY_RANK["medium"]
        observed_label = "MEDIUM"
    elif summary["low"]:
        observed = _SEVERITY_RANK["low"]
        observed_label = "LOW"
    else:
        observed = _SEVERITY_RANK["none"]
        observed_label = "NONE"

    if threshold != _SEVERITY_RANK["none"] and observed >= threshold:
        logger.warning(
            f"Findings at or above '{fail_on}' threshold detected "
            f"(highest observed: {observed_label}) — failing with exit code 2."
        )
        return 2

    logger.info(f"Scan finished cleanly — no findings at or above '{fail_on}' threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
