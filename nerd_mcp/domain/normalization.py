"""Stable normalization and validation shared by application services."""

import ipaddress
import re

from .errors import InventoryError


MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|"
    r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|"
    r"[0-9a-f]{6}-[0-9a-f]{6})(?![0-9a-f])"
)
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").lower()
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise InventoryError(
            "Invalid MAC address; use 12 hexadecimal digits in dotted, colon, or hyphen format."
        )
    if compact == "f" * 12 or int(compact[:2], 16) & 1:
        raise InventoryError(
            "Use an individual unicast MAC address, not broadcast or multicast."
        )
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def valid_interface(value: str) -> str:
    value = value.strip().strip(",")
    return value if re.fullmatch(r"[A-Za-z0-9_.:/-]{1,96}", value) else ""


def safe_label(value: str) -> str:
    value = value.strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", value) else ""


def safe_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[](),")))
    except ValueError:
        return ""


def interface_key(value: str) -> str:
    lowered = re.sub(r"\s+", "", value.casefold())
    aliases = (
        (("hundredgigabitethernet", "hundredgige", "hu"), "hu"),
        (("fortygigabitethernet", "fortygige", "fo"), "fo"),
        (("twentyfivegigabitethernet", "twentyfivegige", "twe"), "twe"),
        (("tengigabitethernet", "tengig", "te"), "te"),
        (("gigabitethernet", "gig", "gi"), "gi"),
        (("fastethernet", "fa"), "fa"),
        (("port-channel", "portchannel", "po"), "po"),
        (("ethernet", "eth", "et", "e"), "e"),
    )
    for names, canonical in aliases:
        for name in names:
            if lowered.startswith(name):
                return canonical + lowered[len(name):]
    return lowered


def normalize_interface(value: str) -> str:
    interface = valid_interface(value or "")
    if not interface:
        raise InventoryError(
            "Invalid interface name; use a device interface such as Gi1/0/18, Et1/1, or 1/1/18."
        )
    return interface_key(interface)
