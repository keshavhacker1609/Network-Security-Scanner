# Automated Network & Security Scanner

A Python-based cybersecurity tool that performs automated network reconnaissance,
detects open ports and running services, classifies security risks, and generates
structured JSON and HTML reports with logging and timestamps.

---

## 🔍 Features

- TCP port scanning using Nmap
- Service detection on open ports
- Risk classification (HIGH / MEDIUM / LOW)
- Timestamped scan execution and duration tracking
- JSON and professional HTML report generation
- Logging to console and log file
- Cross-platform support (Windows / Linux)

---

## 🧠 Project Flow

User Input (Target IP)
↓
Port Scanning
↓
Service Detection
↓
Risk Analysis
↓
Report Generation (JSON + HTML)
↓
Logging & Output Storage

yaml
Copy code

---

## 🛠️ Tech Stack

- Python 3
- Nmap
- YAML (configuration)
- HTML / JSON
- Python logging module

---

## 📁 Project Structure

network_security_scanner/
│
├── config/
│ ├── config.yaml
│ ├── logger.py
│ └── init.py
│
├── scanner/
│ ├── port_scanner.py
│ ├── service_detector.py
│ ├── risk_analyzer.py
│ └── report_generator.py
│
├── reports/
│ ├── json/
│ └── html/
│
├── logs/
│ └── scanner.log
│
├── screenshots/
│ ├── terminal_scan.png
│ └── html_report.png
│
├── main.py
├── requirements.txt
└── README.md

yaml
Copy code

---

## ▶️ Usage

### Prerequisites
- Python 3.x
- Nmap installed and accessible via command line

### Run the scanner
```bash
python main.py --target 127.0.0.1