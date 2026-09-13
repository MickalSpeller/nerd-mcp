"""Endpoint resolution across inventory, ARP, MAC, and topology observations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict

from ..domain.errors import InventoryError
from ..domain.inventory import valid_host
from ..domain.ports import InventoryReader
from ..domain.normalization import normalize_mac

MAX_MAC_CANDIDATES = 16


class EndpointWorkflow:
    """Endpoint resolution workflow with upstream services supplied by its caller."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 mac_service, path_service):
        self.inventory = inventory
        self.mock = mock
        self.mac_service = mac_service
        self.path_service = path_service

    @staticmethod
    def _identifier(value: str) -> tuple[str, str]:
        value = (value or "").strip()
        if not value:
            raise InventoryError("Endpoint identifier is required.")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            if address.version != 4:
                raise InventoryError("IPv6 endpoint discovery is not supported yet.")
            return "ipv4", str(address)
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(compact) == 12 and re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
            return "mac", normalize_mac(value)
        if re.fullmatch(r"[0-9.]+", value):
            raise InventoryError("Invalid IPv4 address.")
        if not valid_host(value) and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", value):
            raise InventoryError(
                "Invalid endpoint identifier; use an IPv4 address, unicast MAC address, "
                "or valid inventoried hostname."
            )
        return "hostname", value.rstrip(".")

    def _inventory_matches(self, kind: str, identifier: str) -> list[dict]:
        key = identifier.casefold()
        matches = []
        for device in self.inventory.list():
            values = {device.name.casefold(), device.host.rstrip(".").casefold()}
            if device.device_hostname:
                values.add(device.device_hostname.rstrip(".").casefold())
            if key in values and (kind == "hostname" or device.host == identifier):
                matches.append(asdict(device))
        return matches

    def locate(self, identifier: str, source_device: str = "",
               max_age_minutes: int = 15, refresh: bool = False,
               workers: int = 4) -> dict[str, object]:
        kind, normalized = self._identifier(identifier)
        if not isinstance(refresh, bool):
            raise InventoryError("refresh must be true or false.")
        if (not isinstance(workers, int) or isinstance(workers, bool)
                or not 1 <= workers <= 16):
            raise InventoryError("workers must be an integer from 1 through 16.")
        if (not isinstance(max_age_minutes, int) or isinstance(max_age_minutes, bool)
                or not 1 <= max_age_minutes <= 10080):
            raise InventoryError("max_age_minutes must be an integer from 1 through 10080.")
        source = self.inventory.get(source_device).name if source_device.strip() else ""
        inventory_matches = self._inventory_matches(kind, normalized)
        if inventory_matches:
            return {
                "status": "success" if len(inventory_matches) == 1 else "partial",
                "complete": len(inventory_matches) == 1,
                "found": True,
                "attachment_found": False,
                "identifier": identifier,
                "normalized_identifier": normalized,
                "identifier_type": kind,
                "resolution": "inventory",
                "inventory_devices": inventory_matches,
                "ip_address": normalized if kind == "ipv4" else "",
                "mac_addresses": [],
                "endpoints": [],
                "incomplete_devices": [],
                "warnings": [] if len(inventory_matches) == 1 else [
                    "The identifier matches more than one inventory device."
                ],
                "max_age_minutes": max_age_minutes,
                "refreshed": False,
                "mock": False,
            }
        if kind == "hostname":
            return {
                "status": "partial", "complete": False, "found": False,
                "attachment_found": False,
                "identifier": identifier, "normalized_identifier": normalized,
                "identifier_type": kind, "resolution": "unresolved",
                "inventory_devices": [], "ip_address": "", "mac_addresses": [],
                "endpoints": [], "incomplete_devices": [],
                "warnings": [
                    "Hostname is not an inventoried device. NERD does not currently ingest "
                    "DHCP or DNS endpoint-name records."
                ],
                "max_age_minutes": max_age_minutes, "refreshed": False, "mock": False,
            }

        collection = self.mac_service.scan("all", workers) if refresh else None
        if kind == "ipv4":
            lookup = self.mac_service.locate_ip(normalized, max_age_minutes)
            macs = lookup["mac_addresses"]
            ip_address = normalized
        else:
            lookup = self.mac_service.locate(normalized, max_age_minutes)
            macs = [normalized]
            ip_address = lookup["ip_addresses"][0] if len(lookup["ip_addresses"]) == 1 else ""

        warnings = []
        if len(macs) > MAX_MAC_CANDIDATES:
            warnings.append(
                f"The identifier resolved to more than {MAX_MAC_CANDIDATES} MAC addresses; "
                "only the first candidates were traced."
            )
            macs = macs[:MAX_MAC_CANDIDATES]
        endpoints = [
            self.path_service.trace(mac, source, max_age_minutes, False, workers)
            for mac in macs
        ]
        incomplete = {
            (row.get("source", "mac"), row["device"]): row
            for endpoint in endpoints for row in endpoint.get("incomplete_devices", [])
        }
        for row in lookup.get("incomplete_devices", []):
            incomplete.setdefault(("arp" if kind == "ipv4" else "mac", row["device"]), {
                "source": "arp" if kind == "ipv4" else "mac", **row,
            })
        attachment_found = any(endpoint.get("endpoint") for endpoint in endpoints)
        found = bool(macs) and any(endpoint.get("found") for endpoint in endpoints)
        complete = bool(
            lookup["complete"] and len(endpoints) == 1
            and endpoints[0].get("endpoint") and not incomplete
        )
        if not lookup["found"]:
            warnings.append(lookup["message"])
        if len(macs) > 1:
            warnings.append("The IPv4 address maps to multiple MAC addresses in current observations.")
        for endpoint in endpoints:
            warnings.extend(endpoint.get("warnings", []))
        result = {
            "status": "success" if complete else "partial",
            "complete": complete,
            "found": found,
            "attachment_found": attachment_found,
            "identifier": identifier,
            "normalized_identifier": normalized,
            "identifier_type": kind,
            "resolution": "network_observations",
            "inventory_devices": [],
            "ip_address": ip_address,
            "mac_addresses": macs,
            "endpoints": endpoints,
            "incomplete_devices": list(incomplete.values()),
            "warnings": list(dict.fromkeys(warnings)),
            "max_age_minutes": max_age_minutes,
            "refreshed": refresh,
            "mock": bool(lookup.get("mock") or any(row.get("mock") for row in endpoints)),
        }
        if collection is not None:
            result["collection_status"] = collection.get("status", "")
            result["collection_counts"] = collection.get("counts", {})
        return result
