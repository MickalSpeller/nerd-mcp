"""Inventory identity, validation limits, and errors independent of storage."""

import ipaddress
import re
from dataclasses import dataclass, fields

from .errors import InventoryError


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    port: int = 22
    credential_profile: str = "default"
    device_hostname: str = ""
    location: str = ""
    street_address: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country: str = ""
    serial_number: str = ""
    model: str = ""
    device_type: str = ""
    vendor: str = "Cisco"
    platform: str = "IOS/IOS-XE"
    facts_updated_at: str = ""
    location_source: str = ""


DEVICE_FIELDS = tuple(field.name for field in fields(Device))
IMPORT_FIELDS = set(DEVICE_FIELDS) - {"facts_updated_at", "location_source"}
TEXT_LIMITS = {
    "device_hostname": 253,
    "location": 200,
    "street_address": 200,
    "city": 100,
    "state": 64,
    "zip_code": 32,
    "serial_number": 128,
    "model": 128,
    "device_type": 64,
    "vendor": 64,
    "platform": 64,
}


def validate_inventory_text(field: str, value: str) -> str:
    """Validate bounded printable inventory metadata."""
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError(f"{field} contains control characters")
    if len(value) > TEXT_LIMITS[field]:
        raise ValueError(f"{field} exceeds {TEXT_LIMITS[field]} characters")
    return value


def valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return "%" not in host
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host):
            return False
        return len(host) <= 253 and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in host.rstrip(".").split(".")
        )
