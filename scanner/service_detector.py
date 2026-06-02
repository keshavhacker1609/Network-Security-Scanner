# Service detection is now integrated directly into port_scanner.run_scan().
# A single nmap pass with -sV retrieves both open ports and their service/version
# details, eliminating the duplicate network round-trip that existed previously.
#
# This module is kept for backwards compatibility only.
# Import run_scan from scanner.port_scanner instead.

from scanner.port_scanner import run_scan  # noqa: F401
