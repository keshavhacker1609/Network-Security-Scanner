"""
Report generator: produces a structured JSON file and a self-contained,
dark-themed HTML report from enriched scan results.
"""

import json
import os
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger("NetworkSecurityScanner")

_RISK_BADGE = {
    "HIGH":   '<span class="badge badge-high">HIGH</span>',
    "MEDIUM": '<span class="badge badge-medium">MEDIUM</span>',
    "LOW":    '<span class="badge badge-low">LOW</span>',
}

_GRADE_CLASS = {
    "CRITICAL": "score-critical",
    "HIGH":     "score-high",
    "MEDIUM":   "score-medium",
    "LOW":      "score-low",
}


def generate_reports(
    data: Dict[str, Any],
    output_dir: str,
    scan_id: str,
    target: str,
    formats: List[str] = None,
) -> Dict[str, str]:
    """
    Writes report files to *output_dir* and returns a dict of {format: path}.

    Parameters
    ----------
    data       : Full report dict produced by main.py.
    output_dir : Base directory (sub-dirs json/ and html/ are created automatically).
    scan_id    : Timestamp-based identifier used in file names.
    target     : Original scan target string (used in titles).
    formats    : List of 'json' and/or 'html' (defaults to both).
    """
    if formats is None:
        formats = ["json", "html"]

    safe_target = target.replace("/", "_").replace(".", "_").replace(":", "_")
    paths: Dict[str, str] = {}

    if "json" in formats:
        json_dir = os.path.join(output_dir, "json")
        os.makedirs(json_dir, exist_ok=True)
        json_path = os.path.join(json_dir, f"{safe_target}_{scan_id}.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.debug(f"JSON report written: {json_path}")
        paths["json"] = json_path

    if "html" in formats:
        html_dir = os.path.join(output_dir, "html")
        os.makedirs(html_dir, exist_ok=True)
        html_path = os.path.join(html_dir, f"{safe_target}_{scan_id}.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(_render_html(data, target))
        logger.debug(f"HTML report written: {html_path}")
        paths["html"] = html_path

    return paths


# ─────────────────────────────────────────────────────────────────────────────
# HTML rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

def _render_html(data: Dict[str, Any], target: str) -> str:
    summary  = data.get("summary", {})
    results  = data.get("results", {})
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    host_sections = "\n".join(_render_host(ip, hd) for ip, hd in results.items())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NSS Report — {target}</title>
  <style>
    /* ── Reset & base ──────────────────────────────────────── */
    :root {{
      --bg:        #0d1117;
      --surface:   #161b22;
      --surface2:  #1c2128;
      --border:    #30363d;
      --text:      #e6edf3;
      --muted:     #8b949e;
      --high:      #f85149;
      --medium:    #d29922;
      --low:       #3fb950;
      --info:      #58a6ff;
      --critical:  #ff6e6e;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
      line-height: 1.6;
      padding: 32px 40px;
    }}

    /* ── Typography ────────────────────────────────────────── */
    h1 {{ font-size: 26px; font-weight: 700; color: var(--info); }}
    h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
    h3 {{ font-size: 15px; font-weight: 600; }}
    a  {{ color: var(--info); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }}

    /* ── Header ────────────────────────────────────────────── */
    .page-header {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 28px;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .page-header .subtitle {{ color: var(--muted); font-size: 13px; margin-top: 6px; }}
    .scan-id-tag {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      color: var(--muted);
      font-family: monospace;
    }}

    /* ── Metadata grid ─────────────────────────────────────── */
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}
    .meta-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }}
    .meta-card .label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--muted);
    }}
    .meta-card .value {{
      font-family: monospace;
      font-size: 13px;
      margin-top: 4px;
      word-break: break-all;
    }}

    /* ── Stats dashboard ───────────────────────────────────── */
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }}
    .stat-card .label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--muted);
    }}
    .stat-card .value {{
      font-size: 36px;
      font-weight: 700;
      margin-top: 8px;
    }}
    .stat-card.c-info     .value {{ color: var(--info);     }}
    .stat-card.c-high     .value {{ color: var(--high);     }}
    .stat-card.c-medium   .value {{ color: var(--medium);   }}
    .stat-card.c-low      .value {{ color: var(--low);      }}
    .stat-card.c-critical .value {{ color: var(--critical); }}

    /* ── Host section ──────────────────────────────────────── */
    .host-block {{
      margin-bottom: 36px;
    }}
    .host-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px 8px 0 0;
      padding: 14px 20px;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .host-title {{
      font-size: 16px;
      font-weight: 600;
      color: var(--info);
      font-family: monospace;
    }}
    .host-meta {{ color: var(--muted); font-size: 12px; margin-top: 3px; }}
    .score-pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 700;
      border: 2px solid;
    }}
    .score-critical {{ color: var(--critical); border-color: var(--critical); background: rgba(255,110,110,.08); }}
    .score-high     {{ color: var(--high);     border-color: var(--high);     background: rgba(248,81,73,.08); }}
    .score-medium   {{ color: var(--medium);   border-color: var(--medium);   background: rgba(210,153,34,.08); }}
    .score-low      {{ color: var(--low);      border-color: var(--low);      background: rgba(63,185,80,.08); }}

    /* ── Findings table ────────────────────────────────────── */
    .findings-wrap {{
      border: 1px solid var(--border);
      border-top: none;
      border-radius: 0 0 8px 8px;
      overflow: hidden;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    thead th {{
      padding: 10px 14px;
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--muted);
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
    }}
    tbody td {{
      padding: 11px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover {{ background: rgba(255,255,255,0.025); }}
    .port-num  {{ font-family: monospace; color: var(--info); font-weight: 600; }}
    .svc-name  {{ font-weight: 500; }}
    .svc-ver   {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
    .cvss-val  {{ font-family: monospace; font-size: 12px; }}
    .cve-list  {{ font-family: monospace; font-size: 11px; color: var(--high); }}
    .remediation-text {{ color: var(--muted); font-size: 12px; font-style: italic; max-width: 320px; }}
    .risk-desc {{ color: var(--muted); font-size: 12px; max-width: 280px; }}

    /* ── Badges ────────────────────────────────────────────── */
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.6px;
      white-space: nowrap;
    }}
    .badge-high   {{ background: rgba(248,81,73,.15);  color: var(--high);   border: 1px solid rgba(248,81,73,.4);  }}
    .badge-medium {{ background: rgba(210,153,34,.15); color: var(--medium); border: 1px solid rgba(210,153,34,.4); }}
    .badge-low    {{ background: rgba(63,185,80,.15);  color: var(--low);    border: 1px solid rgba(63,185,80,.4);  }}

    /* ── Empty state ───────────────────────────────────────── */
    .empty-state {{
      text-align: center;
      padding: 40px;
      color: var(--muted);
      font-size: 14px;
      border: 1px dashed var(--border);
      border-radius: 8px;
      margin-bottom: 24px;
    }}

    /* ── Footer ────────────────────────────────────────────── */
    footer {{
      margin-top: 48px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      text-align: center;
      color: var(--muted);
      font-size: 12px;
    }}
  </style>
</head>
<body>

<div class="page-header">
  <div>
    <h1>Network Security Scan Report</h1>
    <div class="subtitle">Automated reconnaissance &amp; risk classification</div>
  </div>
  <div class="scan-id-tag">Scan ID: {data.get("scan_id", "—")}</div>
</div>

<!-- ── Scan metadata ──────────────────────────────────── -->
<div class="meta-grid">
  <div class="meta-card"><div class="label">Target</div><div class="value">{data.get("target", "—")}</div></div>
  <div class="meta-card"><div class="label">Scan Type</div><div class="value">{data.get("scan_type", "—")}</div></div>
  <div class="meta-card"><div class="label">Ports Scanned</div><div class="value">{data.get("port_spec", "—")}</div></div>
  <div class="meta-card"><div class="label">Start Time</div><div class="value">{data.get("scan_start", "—")}</div></div>
  <div class="meta-card"><div class="label">End Time</div><div class="value">{data.get("scan_end", "—")}</div></div>
  <div class="meta-card"><div class="label">Duration</div><div class="value">{data.get("scan_duration_seconds", 0)} s</div></div>
  <div class="meta-card"><div class="label">Scanner Version</div><div class="value">{data.get("scanner_version", "—")}</div></div>
  <div class="meta-card"><div class="label">Nmap Arguments</div><div class="value">{data.get("nmap_arguments", "—")}</div></div>
</div>

<!-- ── Summary dashboard ──────────────────────────────── -->
<div class="stats-grid">
  <div class="stat-card c-info">
    <div class="label">Hosts Found</div>
    <div class="value">{summary.get("hosts", 0)}</div>
  </div>
  <div class="stat-card c-info">
    <div class="label">Open Ports</div>
    <div class="value">{summary.get("total_open_ports", 0)}</div>
  </div>
  <div class="stat-card c-high">
    <div class="label">High Risk</div>
    <div class="value">{summary.get("high", 0)}</div>
  </div>
  <div class="stat-card c-medium">
    <div class="label">Medium Risk</div>
    <div class="value">{summary.get("medium", 0)}</div>
  </div>
  <div class="stat-card c-low">
    <div class="label">Low Risk</div>
    <div class="value">{summary.get("low", 0)}</div>
  </div>
</div>

<!-- ── Per-host results ───────────────────────────────── -->
{host_sections if host_sections else '<div class="empty-state">No live hosts discovered for the given target.</div>'}

<footer>
  Generated by <strong>Network Security Scanner v{data.get("scanner_version", "2.0.0")}</strong>
  &nbsp;·&nbsp; {gen_time}
  &nbsp;·&nbsp; For authorised security assessment use only.
</footer>

</body>
</html>"""


def _render_host(ip: str, host_data: Dict[str, Any]) -> str:
    findings   = host_data.get("findings", [])
    score_data = host_data.get("risk_score", {})
    score      = score_data.get("score", 0)
    grade      = score_data.get("grade", "LOW")
    hostname   = host_data.get("hostname", ip)
    os_guess   = host_data.get("os_detection", {}).get("guessed", "Unknown")
    state      = host_data.get("state", "unknown")
    grade_cls  = _GRADE_CLASS.get(grade, "score-low")

    host_display = f"{ip}" if hostname == ip else f"{ip} ({hostname})"

    score_pill = (
        f'<div class="score-pill {grade_cls}">'
        f'Score: {score}/100 &nbsp; {grade}'
        f"</div>"
    )

    if not findings:
        body = '<div class="empty-state" style="border-radius:0 0 8px 8px;border-top:none;">No open ports detected on this host.</div>'
        return f"""
<div class="host-block">
  <div class="host-header">
    <div>
      <div class="host-title">{host_display}</div>
      <div class="host-meta">State: {state} &nbsp;·&nbsp; OS: {os_guess}</div>
    </div>
    {score_pill}
  </div>
  {body}
</div>"""

    rows = "".join(_render_row(f) for f in findings)

    return f"""
<div class="host-block">
  <div class="host-header">
    <div>
      <div class="host-title">{host_display}</div>
      <div class="host-meta">State: {state} &nbsp;·&nbsp; OS: {os_guess}</div>
    </div>
    {score_pill}
  </div>
  <div class="findings-wrap">
    <table>
      <thead>
        <tr>
          <th>Port / Proto</th>
          <th>Service</th>
          <th>Risk</th>
          <th>CVSS</th>
          <th>CVE Examples</th>
          <th>Description &amp; Remediation</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>"""


def _render_row(f: Dict[str, Any]) -> str:
    port      = f.get("port", "?")
    proto     = f.get("protocol", "tcp").upper()
    service   = f.get("service", "unknown")
    product   = f.get("product", "")
    version   = f.get("version", "")
    level     = f.get("risk_level", "LOW")
    cvss      = f.get("cvss_score", 0.0)
    cves      = f.get("cve_examples", [])
    remediation = f.get("remediation", "")
    description = f.get("risk_description", "")

    badge    = _RISK_BADGE.get(level, _RISK_BADGE["LOW"])
    ver_str  = f"{product} {version}".strip()
    ver_html = f'<div class="svc-ver">{ver_str}</div>' if ver_str else ""

    cvss_html = f'<span class="cvss-val">{cvss:.1f}</span>' if cvss else "—"

    cve_html = ""
    if cves:
        links = " ".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" rel="noopener">{c}</a>'
            for c in cves
        )
        cve_html = f'<div class="cve-list">{links}</div>'
    else:
        cve_html = '<span style="color:var(--muted)">—</span>'

    return f"""
        <tr>
          <td><span class="port-num">{port}/{proto}</span></td>
          <td><span class="svc-name">{service}</span>{ver_html}</td>
          <td>{badge}</td>
          <td>{cvss_html}</td>
          <td>{cve_html}</td>
          <td>
            <div class="risk-desc">{description}</div>
            <div class="remediation-text" style="margin-top:6px;">&#128273; {remediation}</div>
          </td>
        </tr>"""
