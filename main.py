import argparse
import yaml
from scanner.port_scanner import scan_ports
from scanner.service_detector import detect_services
from scanner.risk_analyzer import analyze_risk
from scanner.report_generator import generate_reports

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True)
args = parser.parse_args()

with open("config/config.yaml") as f:
    config = yaml.safe_load(f)

ports = scan_ports(args.target)
services = detect_services(args.target)
risk = analyze_risk(services, config["risk_ports"])

data = {
    "ports": ports,
    "services": services,
    "risk_analysis": risk
}

json_r, html_r = generate_reports(data, args.target.replace(".", "_"))

print("Scan complete")
print("JSON:", json_r)
print("HTML:", html_r)
