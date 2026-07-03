# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.1.0]

### Added
- **Modular risk database** — port intelligence moved to `config/risk_database.yaml`,
  merged via `risk_database_files` so custom/updated intelligence can be dropped in
  without editing core config.
- **Scan history & diff** (`--diff`) — snapshots each scan per target and reports
  newly-opened / newly-closed ports on subsequent runs.
- **CI gating** — `--fail-on {none,low,medium,high,critical}` drives the exit code.
- **New report formats** — CSV, Markdown, and SARIF (GitHub code-scanning) in
  addition to JSON and HTML. `--format` is now repeatable and supports `all`.
- **Test suite** — pytest coverage for validation, risk scoring, all report
  renderers, history diffing, config merging, and CLI helpers.
- **Packaging** — `pyproject.toml` with an `nss` console entry point.
- **CI workflow** — GitHub Actions matrix (Python 3.9 / 3.11 / 3.12).
- MIT `LICENSE`.

### Changed
- `nmap` is imported lazily, so the package loads (and is testable) without it
  installed; a precise error is raised only when a scan is actually attempted.
- Configurable default report formats via `output.default_formats`.

## [2.0.0]

### Added
- Full argparse CLI with structured exit codes.
- 35+ entry risk database with CVSS scores, CVE examples, and remediation.
- Single-pass Nmap scan (ports + service/version + optional OS) with four profiles.
- Weighted 0–100 risk scoring and letter grades.
- Self-contained dark-theme HTML reports and clean JSON output.
- Target/port validation and rotating, colourised logging.
