import json
import os
from datetime import datetime


def generate_reports(data, name):
    # Timestamp for filenames
    time = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Ensure directories exist
    os.makedirs("reports/json", exist_ok=True)
    os.makedirs("reports/html", exist_ok=True)

    # File paths
    json_path = f"reports/json/{name}_{time}.json"
    html_path = f"reports/html/{name}_{time}.html"

    # ---------------- JSON REPORT ----------------
    with open(json_path, "w") as jf:
        json.dump(data, jf, indent=4)

    # ---------------- HTML REPORT ----------------
    html_content = f"""
    <html>
    <head>
        <title>Network Security Scan Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}
            h1 {{
                color: #2c3e50;
            }}
            table {{
                border-collapse: collapse;
                width: 90%;
                margin-bottom: 20px;
            }}
            th, td {{
                border: 1px solid #333;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .high {{ color: red; font-weight: bold; }}
            .medium {{ color: orange; font-weight: bold; }}
            .low {{ color: green; font-weight: bold; }}
        </style>
    </head>
    <body>

    <h1>Network Security Scan Report</h1>

    <p><strong>Target:</strong> {data.get("target")}</p>
    <p><strong>Scan Start Time:</strong> {data.get("scan_start_time")}</p>
    <p><strong>Scan End Time:</strong> {data.get("scan_end_time")}</p>
    <p><strong>Scan Duration:</strong> {data.get("scan_duration_seconds")} seconds</p>

    <hr>

    <h2>Open Ports</h2>
    <ul>
    """

    # -------- OPEN PORTS --------
    for host, proto_data in data.get("ports", {}).items():
        for proto, port_list in proto_data.items():
            for port in port_list:
                html_content += f"<li>{host} - {proto.upper()} port {port}</li>"

    html_content += """
    </ul>

    <h2>Detected Services</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
        </tr>
    """

    # -------- SERVICES --------
    for host, service_list in data.get("services", {}).items():
        for svc in service_list:
            port, service_name = svc
            html_content += f"""
            <tr>
                <td>{host}</td>
                <td>{port}</td>
                <td>{service_name}</td>
            </tr>
            """

    html_content += """
    </table>

    <h2>Risk Analysis</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Risk Level</th>
        </tr>
    """

    # -------- RISK ANALYSIS --------
    for host, risks in data.get("risk_analysis", {}).items():
        for r in risks:
            level = r.get("risk", "").lower()
            html_content += f"""
            <tr>
                <td>{host}</td>
                <td>{r.get("port")}</td>
                <td class="{level}">{r.get("risk")}</td>
            </tr>
            """

    html_content += """
    </table>

    </body>
    </html>
    """

    # Write HTML file
    with open(html_path, "w") as hf:
        hf.write(html_content)

    return json_path, html_path
