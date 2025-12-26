def analyze_risk(services, risk_ports):
    report = {}

    for host, entries in services.items():
        report[host] = []
        for port, service in entries:
            if port in risk_ports["high"]:
                level = "HIGH"
            elif port in risk_ports["medium"]:
                level = "MEDIUM"
            else:
                level = "LOW"

            report[host].append({
                "port": port,
                "service": service,
                "risk": level
            })
    return report
