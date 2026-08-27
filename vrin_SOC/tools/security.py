"""Shared validators for values that reach security-tool command lines."""

import re

# Network interface names: letters, digits, and the characters the kernel
# actually allows (eth0, ens33, br-0, vlan.10, lo:0). Anything else is
# rejected before an interface reaches a suricata/snort/tcpdump/tshark
# command line, so extra flags can never be smuggled through the value.
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")


def validate_interface(interface: str):
    """Allowlist-check a network interface name.

    Returns ``(ok, value_or_error)`` — the caller either uses the normalized
    name or surfaces the error. Used as defense-in-depth beneath the FastAPI
    ``pattern`` validation on the incident endpoints.
    """
    value = (interface or "").strip()
    if not value or not INTERFACE_RE.fullmatch(value):
        return False, f"invalid interface name: {interface!r}"
    return True, value
