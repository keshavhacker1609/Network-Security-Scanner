import argparse
import yaml
import time
from datetime import datetime

from config.logger import setup_logger
from scanner.port_scanner import scan_ports
from scanner.service_detector import detect_services
from scanner.risk_analyzer import analyze_risk
from scanner.report_generator import generate_reports

logger = setup_logger()
logger.info("Network Security Scanner started")

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True)
args = parser.parse_args()

with open("config/config.yaml") as f:
    config = yaml.safe_load(f)

scan_start_time = time.time()
scan_start_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

logger.info(f"Scan started for target: {args.target}")
logger.info(f"Scan start time: {scan_start_timestamp}")

logger.info("Starting port scan")
ports = scan_ports(args.target)

logger.info("Detecting services")
services = detect_services(args.target)

logger.info("Analyzing risk")
risk = analyze_risk(services, config["risk_ports"])

scan_end_time = time.time()
scan_end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
scan_duration = round(scan_end_time - scan_start_time, 2)

logger.info(f"Scan completed at: {scan_end_timestamp}")
logger.info(f"Total scan duration: {scan_duration} seconds")

data = {
    "target": args.target,
    "scan_start_time": scan_start_timestamp,
    "scan_end_time": scan_end_timestamp,
    "scan_duration_seconds": scan_duration,
    "ports": ports,
    "services": services,
    "risk_analysis": risk
}

logger.info("Generating reports")
json_r, html_r = generate_reports(data, args.target.replace(".", "_"))

logger.info("Scan completed successfully")
logger.info(f"JSON report saved at: {json_r}")
logger.info(f"HTML report saved at: {html_r}")
