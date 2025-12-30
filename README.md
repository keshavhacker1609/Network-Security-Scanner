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

- Python 3
- Nmap
- YAML (configuration)
- HTML / JSON
- Logging module


## ▶️ Usage

### Prerequisites
- Python 3.x
- Nmap installed and accessible via CLI

### Run the scanner
```bash
python main.py --target 127.0.0.1