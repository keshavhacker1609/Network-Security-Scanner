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


VERSION = "2.0.0"


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
  0  Clean — no high-risk findings
  1  Error — scan or config failure
  2  Warning — one or more HIGH-risk ports found
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
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both).",
    )
    out_group.add_argument(
        "--no-report",
        action="store_true",
        help="Skip writing report files; print summary to console only.",
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
    formats    = ["both"] if args.format == "both" else [args.format]
    if "both" in formats:
        formats = ["json", "html"]

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

    # ── Exit code reflects overall risk ──────────────────────
    high_count = report_data["summary"]["high"]
    if high_count:
        logger.warning(f"{high_count} HIGH-risk port(s) detected — review the report immediately.")
        return 2

    logger.info("Scan finished cleanly — no high-risk findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
