"""
Input validation for scan targets and port specifications.
All public functions return (is_valid: bool, message: str).
"""

import ipaddress
import re
import socket
import logging
from typing import Tuple

logger = logging.getLogger("NetworkSecurityScanner")

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Accepts an IPv4/IPv6 address, a RFC-1123 hostname, or a CIDR range.
    CIDR ranges are capped at /16 (65 536 hosts) to prevent accidental wide sweeps.
    Returns (True, kind) on success or (False, human-readable error) on failure.
    """
    target = target.strip()
    if not target:
        return False, "Target must not be empty."

    # Plain IP address (v4 or v6) — checked first so a bare address is not
    # mislabelled as a CIDR range (it parses as a valid /32 or /128 network).
    try:
        ipaddress.ip_address(target)
        return True, "ip"
    except ValueError:
        pass

    # CIDR range
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 65_536:
            return False, (
                f"CIDR range '{target}' covers {net.num_addresses:,} hosts. "
                "Narrow the range to /16 or smaller."
            )
        return True, "cidr"
    except ValueError:
        pass

    # RFC-1123 hostname
    if _HOSTNAME_RE.match(target):
        return True, "hostname"

    return False, (
        f"'{target}' is not a valid IPv4/IPv6 address, CIDR range, or hostname."
    )


def validate_ports(port_spec: str) -> Tuple[bool, str]:
    """
    Validates a port specification and returns the normalised form.
    Accepts: single port (80), range (1-1024), comma list (80,443,8080),
    or the special tokens 'all' / 'full' (expanded to 1-65535).
    """
    port_spec = port_spec.strip()

    if port_spec.lower() in ("all", "full"):
        return True, "1-65535"

    if not re.match(r"^[\d,\-]+$", port_spec):
        return False, (
            f"Invalid port specification '{port_spec}'. "
            "Use: 80  |  1-1024  |  80,443,8080"
        )

    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            halves = part.split("-", 1)
            try:
                lo, hi = int(halves[0]), int(halves[1])
            except ValueError:
                return False, f"Invalid port range: '{part}'."
            if not (0 <= lo <= 65_535 and 0 <= hi <= 65_535):
                return False, f"Port numbers must be 0-65535 (got '{part}')."
            if lo > hi:
                return False, f"Range start must be ≤ end (got '{part}')."
        else:
            try:
                port = int(part)
            except ValueError:
                return False, f"Invalid port: '{part}'."
            if not 0 <= port <= 65_535:
                return False, f"Port {port} is out of the valid range 0-65535."

    return True, port_spec


def resolve_hostname(target: str) -> str:
    """Best-effort hostname → IP resolution for display purposes.  Returns target unchanged on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target
