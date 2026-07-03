# Network Security Scanner (NSS)

A Python-based cybersecurity tool for automated network reconnaissance. It
discovers live hosts, detects open ports and running service versions,
classifies each finding against a curated risk database (CVSS + CVE + remediation
guidance), tracks changes across scans, and produces reports in multiple formats
suitable for both humans and CI pipelines.

> **For authorised security assessment use only.** Scan only systems you own or
> have explicit written permission to test.

---

## Features

- **Single-pass Nmap scanning** — ports, service/version detection, and optional
  OS fingerprinting in one network round-trip.
- **Four scan profiles** — `quick`, `standard`, `aggressive`, `stealth`.
- **Modular risk database** — port intelligence (CVSS scores, CVE examples, and
  remediation) lives in its own YAML file and can be extended or overridden by
  dropping in additional files. Nothing about the risk logic is hard-coded.
- **Weighted risk scoring** — every host receives a 0–100 score and a
  `LOW / MEDIUM / HIGH / CRITICAL` grade.
- **Scan history & diff** — snapshots each scan per target and reports
  newly-opened / newly-closed ports on the next run (`--diff`), ideal for
  continuous monitoring.
- **Multiple report formats** — JSON, self-contained dark-theme HTML, CSV,
  Markdown, and **SARIF** (uploadable to GitHub code-scanning).
- **CI gating** — `--fail-on {none,low,medium,high,critical}` controls the exit
  code so scans can gate a pipeline.
- **Robust input validation** — IPv4/IPv6, hostnames, and CIDR ranges (capped at
  `/16` to prevent accidental wide sweeps).
- **Rotating, colourised logging** — configurable level, size-based rotation.

---

## Requirements

- Python 3.9+
- [Nmap](https://nmap.org/) installed and on your `PATH`
- Python packages: `pip install -r requirements.txt`

Some scan profiles (`-sS`, `-O`) require elevated privileges (root / Administrator).

---

## Installation

```bash
git clone https://github.com/keshavhacker1609/Network-Security-Scanner.git
cd Network-Security-Scanner
pip install -r requirements.txt
```

---

## Usage

```bash
# Standard scan of a single host
python main.py --target 192.168.1.1

# Aggressive scan of a subnet, JSON + SARIF output
python main.py --target 192.168.1.0/24 --scan-type aggressive -f json -f sarif

# Specific ports, compare against the previous scan, fail CI on HIGH findings
python main.py --target example.com --ports 80,443,8080 --diff --fail-on high

# Stealth scan, all report formats, custom output directory
python main.py --target 10.0.0.1 --scan-type stealth -f all -o ./reports
```

### Key options

| Flag | Description |
|------|-------------|
| `--target, -t` | IPv4/IPv6 address, hostname, or CIDR range (required) |
| `--ports, -p` | `80` \| `1-1024` \| `80,443,8080` \| `all` |
| `--scan-type, -s` | `quick` \| `standard` \| `aggressive` \| `stealth` |
| `--format, -f` | `json` \| `html` \| `csv` \| `markdown` \| `sarif` \| `both` \| `all` (repeatable) |
| `--diff` | Compare against the previous scan of this target |
| `--no-history` | Do not persist a snapshot for future diffs |
| `--fail-on` | Severity that triggers a non-zero exit (CI gating) |
| `--output-dir, -o` | Report output directory |
| `--config, -c` | Path to a custom `config.yaml` |
| `--verbose, -v` | DEBUG-level logging |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above the `--fail-on` threshold |
| `1` | Error — scan or configuration failure |
| `2` | Gate — a finding at or above the threshold was found |
| `130` | Interrupted (Ctrl-C) |

---

## Configuration

All behaviour is driven by [`config/config.yaml`](config/config.yaml) — scan
timeout, logging, output defaults, history, and the CI `fail_on` threshold.

The risk database is **modular**. Base intelligence lives in
[`config/risk_database.yaml`](config/risk_database.yaml); list additional files
under `risk_database_files` to merge in your own port intelligence without
editing the base file. Later files (and the optional inline `risk_database`
block) take precedence, so updates and overrides are drop-in.

```yaml
risk_database_files:
  - "risk_database.yaml"
  - "custom_ports.yaml"   # your additions/overrides
```

---

## Project structure

```
main.py                     CLI entry point and orchestration
config/
  config.yaml               Runtime settings + risk-database references
  risk_database.yaml        Modular port-risk intelligence
  __init__.py               Config loader (merges modular DB files)
  logger.py                 Rotating, colourised logging
scanner/
  port_scanner.py           Single-pass Nmap scan + profiles
  risk_analyzer.py          Risk classification & weighted scoring
  report_generator.py       JSON / HTML / CSV / Markdown / SARIF reports
  history.py                Snapshot persistence & scan diffing
  validator.py              Target & port-spec validation
```

---

## License

Provided for educational and authorised security-assessment purposes.
