"""Vendor-adapted MAC collection, current-observation storage, and endpoint location."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from inspect import getattr_static

from ..domain.models import MacObservation
from ..domain.errors import InventoryError
from ..domain.inventory import Device
from ..domain.normalization import (
    interface_key as _public_interface_key,
    normalize_interface as _public_normalize_interface,
    normalize_mac as _public_normalize_mac,
)
from ..domain.ports import DeviceTransportPort, InventoryPort, ObservationRepositoryPort

normalize_mac = _public_normalize_mac
normalize_interface = _public_normalize_interface
_interface_key = _public_interface_key


class MacWorkflow:
    """Observation workflow with storage and transport supplied by its caller."""

    def __init__(self, inventory: InventoryPort, mock: bool,
                 repository: ObservationRepositoryPort,
                 transport: DeviceTransportPort, capability_provider,
                 error_mapper, command_rejected,
                 max_command_output_chars: int = 5_000_000):
        self.inventory = inventory
        self.mock = mock
        self.index = repository
        self.transport = transport
        self.capabilities = capability_provider
        self.error_mapper = error_mapper
        self.command_rejected = command_rejected
        self.max_command_output_chars = max_command_output_chars

    def _run_commands(self, device: Device, adapter,
                      command_keys: set[str] | None = None) -> tuple[dict[str, str], list[str]]:
        selected = {
            key: commands for key, commands in adapter.commands.items()
            if command_keys is None or key in command_keys
        }
        if self.mock:
            fixture = adapter.collector.MOCK_OUTPUTS
            return {key: fixture.get(key, "") for key in selected}, [
                commands[0] for commands in selected.values()
            ]
        with self.transport.connection(
            device, adapter.netmiko_type, 60
        ) as (connection, password):
            return self._send_commands(connection, password, adapter, selected)

    def _send_commands(self, connection, password: str, adapter,
                       selected: dict[str, tuple[str, ...]]) -> tuple[dict[str, str], list[str]]:
        outputs = {}
        used = []
        for key, alternatives in selected.items():
            output = ""
            for command in alternatives:
                used.append(command)
                output = str(connection.send_command(command, read_timeout=60))
                if len(output) > self.max_command_output_chars:
                    raise InventoryError(
                        f"Output for {command!r} exceeds the "
                        f"{self.max_command_output_chars:,}-character limit."
                    )
                if not self.command_rejected(output):
                    break
            outputs[key] = output.replace(password, "[REDACTED]")
        followup = getattr_static(adapter.collector, "followup_commands", None)
        if callable(followup):
            collected: dict[str, list[str]] = {}
            for output_key, command in followup(outputs):
                used.append(command)
                output = str(connection.send_command(command, read_timeout=60))
                if len(output) > self.max_command_output_chars:
                    raise InventoryError(
                        f"Output for {command!r} exceeds the "
                        f"{self.max_command_output_chars:,}-character limit."
                    )
                collected.setdefault(output_key, []).append(
                    output.replace(password, "[REDACTED]")
                )
            for output_key, values in collected.items():
                outputs[output_key] = "\n".join(values)
        return outputs, used

    def _collect_neighbors_one(self, device: Device) -> dict[str, object]:
        timestamp = datetime.now(timezone.utc).isoformat()
        result = {
            "device": device.name, "vendor": device.vendor, "platform": device.platform,
            "timestamp": timestamp, "status": "error", "commands": [],
            "neighbor_count": 0, "warning": None, "error": None, "mock": self.mock,
        }
        adapter = self.capabilities.observation_adapter_for(device)
        protocols = {
            key for key in ("cdp", "lldp") if adapter and key in adapter.commands
        }
        if not adapter or not protocols:
            result.update({
                "status": "unsupported",
                "error": "No CDP or LLDP collection command is available for this platform.",
            })
            self.index.record_topology_failure(
                device.name, timestamp, "unsupported", result["error"]
            )
            return result
        try:
            outputs, used = self._run_commands(device, adapter, protocols)
            result["commands"] = used
            available = [
                key for key in protocols if not self.command_rejected(outputs.get(key, ""))
            ]
            batch = adapter.collector.parse_observations(outputs)
            neighbors = list(batch.neighbors)
            status = "success" if available else "partial"
            warning = (
                None if status == "success" else
                "CDP and LLDP commands were unsupported or not permitted."
            )
            if status == "success":
                self.index.replace_neighbors(
                    device.name, timestamp, status, warning, neighbors, mock=self.mock
                )
            else:
                self.index.record_topology_failure(
                    device.name, timestamp, status, warning
                )
            result.update({
                "status": status, "neighbor_count": len(neighbors), "warning": warning,
            })
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
            self.index.record_topology_failure(
                device.name, timestamp, "error", result["error"]
            )
        return result

    def _collect_one(self, device: Device) -> dict[str, object]:
        timestamp = datetime.now(timezone.utc).isoformat()
        result = {
            "device": device.name, "vendor": device.vendor, "platform": device.platform,
            "timestamp": timestamp, "status": "error", "commands": [], "mac_count": 0,
            "arp_count": 0, "neighbor_count": 0, "interface_count": 0,
            "warning": None, "error": None, "mock": self.mock,
        }
        adapter = self.capabilities.observation_adapter_for(device)
        if adapter is None:
            result.update({"status": "unsupported", "error": "No MAC collection adapter is available for this vendor/platform."})
            self.index.record_failure(device.name, timestamp, "unsupported", result["error"])
            return result
        try:
            outputs, used = self._run_commands(device, adapter)
            result["commands"] = used
            mac_supported = bool(outputs.get("mac", "").strip()) and not self.command_rejected(outputs["mac"])
            arp_supported = bool(outputs.get("arp", "").strip()) and not self.command_rejected(outputs["arp"])
            batch = adapter.collector.parse_observations(outputs)
            macs = list(batch.macs) if mac_supported else []
            arps = list(batch.arps) if arp_supported else []
            existing_macs = {row.mac for row in macs}
            for arp in arps:
                if arp.mac not in existing_macs and arp.interface:
                    macs.append(MacObservation(arp.mac, "", arp.interface, "arp"))
            uplinks, neighbors = batch.uplinks, list(batch.neighbors)
            uplink_keys = {_interface_key(interface) for interface in uplinks}
            interface_counts = {}
            for row in macs:
                key = _interface_key(row.interface)
                interface_counts[key] = interface_counts.get(key, 0) + 1
            classified = []
            for row in macs:
                key = _interface_key(row.interface)
                if row.entry_type in {"static", "system", "self"}:
                    role = "system"
                elif key in uplink_keys or interface_counts[key] > 10 or key.startswith(("po", "lag", "trk")):
                    role = "uplink"
                elif row.entry_type == "dynamic":
                    role = "access"
                else:
                    role = "unknown"
                classified.append(replace(row, role=role))
            macs = classified
            interfaces = list(batch.interfaces)
            required_supported = mac_supported if device.device_type.casefold() == "switch" else (
                arp_supported if device.device_type.casefold() in {"router", "firewall"} else mac_supported or arp_supported
            )
            status = "success" if required_supported else "partial"
            warning = None if status == "success" else "The expected MAC or ARP command was unavailable; observations are incomplete."
            self.index.replace(
                device.name, timestamp, status, warning, macs, arps, neighbors, interfaces,
                mock=self.mock,
            )
            result.update({
                "status": status, "mac_count": len(macs), "arp_count": len(arps),
                "neighbor_count": len(neighbors), "interface_count": len(interfaces), "warning": warning,
            })
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
            self.index.record_failure(device.name, timestamp, "error", result["error"])
        return result

    def scan(self, target: str, workers: int = 4) -> dict[str, object]:
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
            raise InventoryError("workers must be an integer from 1 through 16.")
        devices = self.inventory.list() if target.casefold() == "all" else [self.inventory.get(target)]
        if not devices:
            raise InventoryError("No devices are inventoried.")
        # Complete schema creation and any migration before worker threads begin writing.
        self.index.prepare()
        results = []
        with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
            pending = {pool.submit(self._collect_one, device): device.name for device in devices}
            for future in as_completed(pending):
                results.append(future.result())
        results.sort(key=lambda row: row["device"])
        counts = {status: sum(row["status"] == status for row in results)
                  for status in ("success", "partial", "error", "unsupported")}
        return {
            "status": "success" if all(row["status"] == "success" for row in results) else "partial",
            "target": target, "timestamp": datetime.now(timezone.utc).isoformat(),
            "counts": counts, "results": results, "mock": self.mock,
        }

    def scan_neighbors(self, target: str, workers: int = 4) -> dict[str, object]:
        """Refresh only CDP/LLDP observations; leave MAC and ARP data untouched."""
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
            raise InventoryError("workers must be an integer from 1 through 16.")
        devices = self.inventory.list() if target.casefold() == "all" else [self.inventory.get(target)]
        if not devices:
            raise InventoryError("No devices are inventoried.")
        self.index.prepare()
        results = []
        with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
            pending = {
                pool.submit(self._collect_neighbors_one, device): device.name
                for device in devices
            }
            for future in as_completed(pending):
                results.append(future.result())
        results.sort(key=lambda row: row["device"])
        counts = {
            status: sum(row["status"] == status for row in results)
            for status in ("success", "partial", "error", "unsupported")
        }
        return {
            "status": "success" if all(row["status"] == "success" for row in results) else "partial",
            "target": target, "timestamp": datetime.now(timezone.utc).isoformat(),
            "counts": counts, "results": results, "mock": self.mock,
            "collector": "neighbors_only",
        }

    def locate(self, mac: str, max_age_minutes: int = 15) -> dict[str, object]:
        mac = normalize_mac(mac)
        self._validate_max_age(max_age_minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        devices = self.inventory.list()
        snapshot = self.index.mac_lookup_rows(mac)
        scans = snapshot["scans"]
        rows = snapshot["matches"]
        arp_rows = snapshot["arps"]
        matched_ports = {
            (row["device_name"], row["interface_key"]) for row in rows
        }
        neighbor_rows = [
            row for row in snapshot["neighbors"]
            if (row["device_name"], row["interface_key"]) in matched_ports
        ]
        failed = self._incomplete_devices(devices, scans, cutoff)
        role_order = {"access": 0, "unknown": 1, "uplink": 2, "system": 3}
        type_order = {
            "dynamic": 0, "secure": 1, "arp": 2, "static": 3,
            "system": 4, "self": 4,
        }
        rows.sort(key=lambda row: (
            role_order.get(row["role"], 2),
            type_order.get(row["entry_type"], 2),
            row["device_name"], row["interface"], row["vlan"],
        ))
        access = [
            row for row in rows
            if row["role"] == "access" and row["entry_type"] == "dynamic"
        ]
        likely = access[0] if access else rows[0] if rows else None
        confidence = (
            "high" if len(access) == 1 else
            "medium" if access else
            "low" if rows else "none"
        )
        ips = sorted({row["ip"] for row in arp_rows}, key=ipaddress.ip_address)
        mock_devices = sorted(
            name for name, scan in scans.items() if scan.get("mock")
        )
        return {
            "status": "success",
            "mac": mac,
            "found": bool(rows),
            "complete": not failed,
            "max_age_minutes": max_age_minutes,
            "likely_endpoint": likely,
            "confidence": confidence,
            "ip_addresses": ips,
            "matches": rows,
            "arp_observations": arp_rows,
            "neighbors": neighbor_rows,
            "incomplete_devices": failed,
            "mock": bool(mock_devices),
            "mock_devices": mock_devices,
            "message": (
                "MAC address located."
                if rows else
                "MAC address was not found in complete current observations."
                if not failed else
                "MAC address was not found, but observations are incomplete or stale."
            ),
        }

    def locate_ip(self, ip_address: str, max_age_minutes: int = 15) -> dict[str, object]:
        try:
            address = ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise InventoryError("Invalid IP address.") from exc
        if address.version != 4:
            raise InventoryError("IPv6 endpoint discovery is not supported yet.")
        self._validate_max_age(max_age_minutes)
        ip = str(address)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        devices = self.inventory.list()
        snapshot = self.index.arp_lookup_rows(ip)
        scans = snapshot["scans"]
        rows = snapshot["arps"]
        incomplete = self._incomplete_devices(devices, scans, cutoff)
        macs = sorted({row["mac"] for row in rows})
        mock_devices = sorted(
            name for name, scan in scans.items() if scan.get("mock")
        )
        return {
            "status": "success",
            "ip_address": ip,
            "found": bool(rows),
            "complete": not incomplete,
            "max_age_minutes": max_age_minutes,
            "mac_addresses": macs,
            "arp_observations": rows,
            "incomplete_devices": incomplete,
            "mock": bool(mock_devices),
            "mock_devices": mock_devices,
            "message": (
                "IPv4 address resolved through current ARP observations."
                if rows else
                "IPv4 address was not found in complete current ARP observations."
                if not incomplete else
                "IPv4 address was not found, but observations are incomplete or stale."
            ),
        }

    def troubleshoot(self, mac: str, max_age_minutes: int = 15) -> dict[str, object]:
        result = self.locate(mac, max_age_minutes)
        issues = []
        access = [row for row in result["matches"] if row["role"] == "access"]
        if not result["complete"]:
            issues.append(
                "One or more devices have missing, stale, or failed observations."
            )
        if not result["found"]:
            issues.append(
                "The MAC may have aged out, may be silent, or may be outside the scanned devices."
            )
        elif not access:
            issues.append(
                "Only uplink, system, or uncertain observations were found; the endpoint port is unresolved."
            )
        elif len(access) > 1:
            issues.append(
                "Multiple access-port candidates were found; check for a MAC move, loop, stack, or stale entry."
            )
        if not result["ip_addresses"]:
            issues.append(
                "No current IPv4 ARP observation maps this MAC to an IP address."
            )
        endpoint = result["likely_endpoint"]
        if endpoint:
            if (endpoint.get("interface_status")
                    and endpoint["interface_status"].casefold() != "up"):
                issues.append(
                    f"Candidate interface status is {endpoint['interface_status']}."
                )
            total_errors = sum(
                endpoint.get(field) or 0
                for field in ("input_errors", "crc_errors", "output_errors")
            )
            if total_errors:
                issues.append(
                    "Candidate interface has nonzero cumulative errors: "
                    f"input {endpoint.get('input_errors') or 0}, "
                    f"CRC {endpoint.get('crc_errors') or 0}, "
                    f"output {endpoint.get('output_errors') or 0}."
                )
        result["issues"] = issues
        result["healthy"] = result["found"] and not issues
        return result

    def interface_macs(self, device: str, interface: str,
                       max_age_minutes: int = 15) -> dict[str, object]:
        record = self.inventory.get(device)
        interface_key = normalize_interface(interface)
        self._validate_max_age(max_age_minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        snapshot = self.index.interface_lookup_rows(record.name)
        scan = snapshot["scan"]
        stale = self._stale(scan, cutoff)
        scan_status = (
            "not_scanned" if not scan else "stale" if stale else scan["status"]
        )
        complete = bool(scan and scan["status"] == "success" and not stale)
        matches = [
            row for row in snapshot["macs"]
            if _interface_key(row["interface"]) == interface_key
        ]
        arp_by_mac: dict[str, set[str]] = {}
        for arp in snapshot["arps"]:
            arp_by_mac.setdefault(arp["mac"], set()).add(arp["ip"])
        role_order = {"access": 0, "unknown": 1, "uplink": 2, "system": 3}
        matches.sort(key=lambda row: (
            role_order.get(row["role"], 2), row["vlan"], row["mac"],
            row["entry_type"],
        ))
        for row in matches:
            row["ip_addresses"] = sorted(
                arp_by_mac.get(row["mac"], set()), key=ipaddress.ip_address
            )
        interface_health = next(
            (
                row for row in snapshot["health"]
                if _interface_key(row["interface"]) == interface_key
            ),
            None,
        )
        matched_interfaces = sorted({row["interface"] for row in matches})
        if matches:
            message = (
                f"Found {len(matches)} MAC observation(s) on "
                f"{record.name} {matched_interfaces[0]}."
            )
        elif complete:
            message = (
                f"No learned MAC addresses were found on {record.name} {interface} "
                "in current observations."
            )
        else:
            message = (
                f"MAC addresses on {record.name} {interface} cannot be determined "
                "because observations are missing, stale, or incomplete."
            )
        return {
            "status": "success",
            "device": record.name,
            "requested_interface": interface,
            "interface_key": interface_key,
            "matched_interfaces": matched_interfaces,
            "found": bool(matches),
            "complete": complete,
            "scan_status": scan_status,
            "observations_at": None if not scan else scan.get("observations_at") or None,
            "max_age_minutes": max_age_minutes,
            "count": len(matches),
            "observations": matches,
            "interface_health": interface_health,
            "error": None if not scan else scan.get("error"),
            "mock": bool(scan and scan.get("mock")),
            "message": message,
        }

    def device_macs(self, device: str,
                    max_age_minutes: int = 15) -> dict[str, object]:
        """List every normalized MAC observation for one inventoried device."""
        record = self.inventory.get(device)
        self._validate_max_age(max_age_minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        snapshot = self.index.device_mac_rows(record.name)
        scan = snapshot["scan"]
        stale = self._stale(scan, cutoff)
        scan_status = (
            "not_scanned" if not scan else "stale" if stale else scan["status"]
        )
        complete = bool(scan and scan["status"] == "success" and not stale)
        arp_by_mac: dict[str, set[str]] = {}
        for arp in snapshot["arps"]:
            arp_by_mac.setdefault(arp["mac"], set()).add(arp["ip"])
        role_order = {"access": 0, "unknown": 1, "uplink": 2, "system": 3}
        rows = []
        for stored in snapshot["macs"]:
            row = {
                key: stored[key]
                for key in (
                    "mac", "vlan", "interface", "entry_type", "role", "observed_at"
                )
            }
            row["ip_addresses"] = sorted(
                arp_by_mac.get(row["mac"], set()), key=ipaddress.ip_address
            )
            rows.append(row)
        rows.sort(key=lambda row: (
            role_order.get(row["role"], 2), _interface_key(row["interface"]),
            row["vlan"], row["mac"], row["entry_type"],
        ))
        if rows:
            message = f"Found {len(rows)} MAC observation(s) on {record.name}."
        elif complete:
            message = (
                f"No learned MAC addresses were found on {record.name} in current observations."
            )
        else:
            message = (
                f"The MAC address table for {record.name} cannot be determined because "
                "observations are missing, stale, or incomplete."
            )
        return {
            "status": "success",
            "device": record.name,
            "found": bool(rows),
            "complete": complete,
            "scan_status": scan_status,
            "observations_at": None if not scan else scan.get("observations_at") or None,
            "max_age_minutes": max_age_minutes,
            "count": len(rows),
            "observations": rows,
            "error": None if not scan else scan.get("error"),
            "mock": bool(scan and scan.get("mock")),
            "message": message,
        }

    def device_arps(self, device: str,
                    max_age_minutes: int = 15) -> dict[str, object]:
        """List every normalized ARP observation for one inventoried device."""
        record = self.inventory.get(device)
        self._validate_max_age(max_age_minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        snapshot = self.index.device_arp_rows(record.name)
        scan = snapshot["scan"]
        stale = self._stale(scan, cutoff)
        scan_status = (
            "not_scanned" if not scan else "stale" if stale else scan["status"]
        )
        complete = bool(scan and scan["status"] == "success" and not stale)
        rows = [
            {
                key: stored[key]
                for key in ("ip", "mac", "interface", "vrf", "observed_at")
            }
            for stored in snapshot["arps"]
        ]
        rows.sort(key=lambda row: (
            ipaddress.ip_address(row["ip"]), row["mac"],
            _interface_key(row["interface"]), row["vrf"],
        ))
        if rows:
            message = f"Found {len(rows)} ARP observation(s) on {record.name}."
        elif complete:
            message = f"No ARP entries were found on {record.name} in current observations."
        else:
            message = (
                f"The ARP table for {record.name} cannot be determined because "
                "observations are missing, stale, or incomplete."
            )
        return {
            "status": "success",
            "device": record.name,
            "found": bool(rows),
            "complete": complete,
            "scan_status": scan_status,
            "observations_at": None if not scan else scan.get("observations_at") or None,
            "max_age_minutes": max_age_minutes,
            "count": len(rows),
            "observations": rows,
            "error": None if not scan else scan.get("error"),
            "mock": bool(scan and scan.get("mock")),
            "message": message,
        }

    @staticmethod
    def _validate_max_age(max_age_minutes: int) -> None:
        if (not isinstance(max_age_minutes, int)
                or isinstance(max_age_minutes, bool)
                or not 1 <= max_age_minutes <= 10_080):
            raise InventoryError(
                "max_age_minutes must be an integer from 1 through 10080."
            )

    @staticmethod
    def _stale(scan: dict | None, cutoff: datetime) -> bool:
        if not scan or not scan.get("observations_at"):
            return True
        try:
            return datetime.fromisoformat(scan["observations_at"]) < cutoff
        except ValueError:
            return True

    @classmethod
    def _incomplete_devices(cls, devices, scans: dict,
                            cutoff: datetime) -> list[dict[str, object]]:
        incomplete = []
        for device in devices:
            scan = scans.get(device.name)
            stale = cls._stale(scan, cutoff)
            if not scan or scan["status"] != "success" or stale:
                incomplete.append({
                    "device": device.name,
                    "status": (
                        "not_scanned" if not scan else
                        "stale" if stale else scan["status"]
                    ),
                    "error": None if not scan else scan.get("error"),
                    "observations_at": (
                        None if not scan else scan.get("observations_at") or None
                    ),
                })
        return incomplete
