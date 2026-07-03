"""
Single-pass nmap scanner: combines port discovery, service/version detection,
and optional OS fingerprinting in one network round-trip.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("NetworkSecurityScanner")


def _import_nmap():
    """Import python-nmap lazily so the package loads without it installed.

    Keeps import-time cheap and gives a precise, actionable error only when a
    scan is actually attempted.
    """
    try:
        import nmap
        return nmap
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'python-nmap' package is not installed. "
            "Install dependencies with: pip install -r requirements.txt"
        ) from exc

# Scan profiles: name → nmap argument string
SCAN_PROFILES: Dict[str, str] = {
    "quick":      "-sV --top-ports 100 -T4",
    "standard":   "-sV --top-ports 1000 -T4",
    "aggressive": "-sV -sC -O --top-ports 1000 -T4",
    "stealth":    "-sS -sV --top-ports 1000 -T2",
}


def run_scan(
    target: str,
    ports: Optional[str] = None,
    scan_profile: str = "standard",
    extra_args: str = "",
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Runs nmap against *target* and returns structured per-host results.

    Parameters
    ----------
    target       : IP, hostname, or CIDR accepted by nmap.
    ports        : Optional port spec (e.g. '1-1024', '80,443').
                   When None the profile's --top-ports setting applies.
    scan_profile : One of SCAN_PROFILES keys.
    extra_args   : Additional nmap flags appended to the profile string.
    timeout      : Hard timeout in seconds passed to python-nmap.

    Returns
    -------
    Dict keyed by discovered host IP, each value being a host-data dict.
    """
    if scan_profile not in SCAN_PROFILES:
        raise ValueError(
            f"Unknown scan profile '{scan_profile}'. "
            f"Choose from: {', '.join(SCAN_PROFILES)}"
        )

    arguments = SCAN_PROFILES[scan_profile]

    # When explicit ports are provided, drop the --top-ports flag so nmap
    # does not silently ignore the -p argument.
    if ports:
        arguments = " ".join(
            tok for tok in arguments.split() if not tok.startswith("--top-ports")
        )

    if extra_args:
        arguments = f"{arguments} {extra_args}"

    nmap = _import_nmap()
    nm = nmap.PortScanner()

    logger.debug(f"nmap arguments: {arguments}")
    logger.info(f"Scanning {target}" + (f" (ports: {ports})" if ports else ""))

    try:
        nm.scan(
            hosts=target,
            ports=ports,
            arguments=arguments,
            timeout=timeout,
        )
    except nmap.PortScannerError as exc:
        raise RuntimeError(
            f"nmap scan failed — ensure nmap is installed and you have "
            f"sufficient privileges.\nDetail: {exc}"
        ) from exc

    results: Dict[str, Any] = {}

    for host in nm.all_hosts():
        host_entry: Dict[str, Any] = {
            "ip":           host,
            "hostname":     nm[host].hostname() or host,
            "state":        nm[host].state(),
            "os_detection": _extract_os(nm, host),
            "protocols":    {},
        }

        for proto in nm[host].all_protocols():
            host_entry["protocols"][proto] = {}
            for port, pdata in nm[host][proto].items():
                host_entry["protocols"][proto][port] = {
                    "state":         pdata.get("state", "unknown"),
                    "service":       pdata.get("name", "unknown"),
                    "product":       pdata.get("product", ""),
                    "version":       pdata.get("version", ""),
                    "extrainfo":     pdata.get("extrainfo", ""),
                    "cpe":           pdata.get("cpe", ""),
                    "reason":        pdata.get("reason", ""),
                    "script_output": pdata.get("script", {}),
                }

        results[host] = host_entry

    if not results:
        logger.warning(f"No live hosts found for target '{target}'.")

    return results


def _extract_os(nm: Any, host: str) -> Dict[str, Any]:
    os_info: Dict[str, Any] = {"guessed": "Unknown", "matches": []}
    try:
        for match in nm[host].get("osmatch", [])[:3]:
            os_info["matches"].append(
                {"name": match.get("name", "Unknown"), "accuracy": match.get("accuracy", "0")}
            )
        if os_info["matches"]:
            os_info["guessed"] = os_info["matches"][0]["name"]
    except Exception:
        pass
    return os_info
