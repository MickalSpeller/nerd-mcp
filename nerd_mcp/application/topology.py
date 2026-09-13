"""Inventory-correlated topology from current CDP and LLDP observations."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from ..domain.errors import InventoryError
from ..domain.inventory import Device
from ..domain.ports import InventoryPort, ObservationRepositoryPort
from ..domain.normalization import interface_key


def _identity(value: str) -> str:
    return (value or "").strip().rstrip(".").casefold()


def _short_identity(value: str) -> str:
    return _identity(value).split(".", 1)[0]


def _as_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return ""


def _observed_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


class TopologyWorkflow:
    """Topology workflow with observation dependencies supplied by its caller."""

    def __init__(self, inventory: InventoryPort, mock: bool, mac_service,
                 repository: ObservationRepositoryPort, capability_provider):
        self.inventory = inventory
        self.mock = mock
        self.mac_service = mac_service
        self.index = repository
        self.capabilities = capability_provider

    @staticmethod
    def _identity_indexes(devices: list[Device]):
        full: dict[str, set[str]] = {}
        short: dict[str, set[str]] = {}
        addresses: dict[str, set[str]] = {}
        for device in devices:
            for value in (device.name, device.device_hostname, device.host):
                if not value:
                    continue
                address = _as_ip(value)
                if address:
                    addresses.setdefault(address, set()).add(device.name)
                    continue
                normalized = _identity(value)
                full.setdefault(normalized, set()).add(device.name)
                short.setdefault(_short_identity(normalized), set()).add(device.name)
        return full, short, addresses

    @staticmethod
    def _resolve_neighbor(row: dict, source: str, indexes) -> dict[str, object]:
        full, short, addresses = indexes
        label = _identity(row.get("neighbor", ""))
        address = _as_ip(row.get("neighbor_address", ""))
        address_matches = set(addresses.get(address, set())) if address else set()
        label_matches = set(full.get(label, set())) if label else set()
        confidence = "high"
        method = "management_address" if address_matches else "identity"
        if not label_matches and label:
            label_matches = set(short.get(_short_identity(label), set()))
            if label_matches:
                confidence = "medium"
                method = "short_identity"
        if address_matches and label_matches:
            candidates = address_matches & label_matches
            if not candidates:
                return {"target": "", "confidence": "none", "method": "conflict",
                        "reason": "Neighbor name and management address match different inventory devices."}
            confidence = "high"
            method = "identity_and_management_address"
        else:
            candidates = address_matches or label_matches
        if len(candidates) > 1:
            return {"target": "", "confidence": "none", "method": method,
                    "reason": "Neighbor identity matches multiple inventory devices."}
        if not candidates:
            return {"target": "", "confidence": "none", "method": "unresolved",
                    "reason": "No inventory device matches the neighbor identity or management address."}
        target = next(iter(candidates))
        if target == source:
            return {"target": "", "confidence": "none", "method": method,
                    "reason": "Neighbor observation resolves to the source device itself."}
        return {"target": target, "confidence": confidence, "method": method, "reason": ""}

    @staticmethod
    def _compact_directed(rows: list[dict]) -> list[dict[str, object]]:
        compact: dict[tuple, dict[str, object]] = {}
        for row in rows:
            remote_key = interface_key(row["remote_interface"]) if row["remote_interface"] else ""
            key = (
                row["source"], row["interface_key"], row["target"], remote_key,
            )
            item = compact.get(key)
            if item is None:
                item = {
                    **row,
                    "remote_interface_key": remote_key,
                    "protocols": set(),
                }
                compact[key] = item
            item["protocols"].add(row["protocol"])
            if row["observed_at"] > item["observed_at"]:
                item["observed_at"] = row["observed_at"]
        return list(compact.values())

    @staticmethod
    def _links(directed: list[dict[str, object]]) -> list[dict[str, object]]:
        links = []
        used: set[int] = set()
        for index, edge in enumerate(directed):
            if index in used:
                continue
            reverse_index = None
            reverse_score = -1
            for candidate_index in range(index + 1, len(directed)):
                if candidate_index in used:
                    continue
                candidate = directed[candidate_index]
                if candidate["source"] != edge["target"] or candidate["target"] != edge["source"]:
                    continue
                if not edge["remote_interface_key"] and not candidate["remote_interface_key"]:
                    continue
                if (edge["remote_interface_key"]
                        and edge["remote_interface_key"] != candidate["interface_key"]):
                    continue
                if (candidate["remote_interface_key"]
                        and candidate["remote_interface_key"] != edge["interface_key"]):
                    continue
                score = int(bool(edge["remote_interface_key"])) + int(bool(candidate["remote_interface_key"]))
                if score > reverse_score:
                    reverse_index, reverse_score = candidate_index, score
            reverse = directed[reverse_index] if reverse_index is not None else None
            used.add(index)
            if reverse_index is not None:
                used.add(reverse_index)
            endpoint_a = {
                "device": edge["source"], "interface": edge["interface"],
            }
            endpoint_b = {
                "device": edge["target"],
                "interface": (
                    reverse["interface"] if reverse else edge["remote_interface"]
                ),
            }
            if endpoint_b["device"].casefold() < endpoint_a["device"].casefold():
                endpoint_a, endpoint_b = endpoint_b, endpoint_a
            confidences = [edge["confidence"]]
            protocols = set(edge["protocols"])
            observed = edge["observed_at"]
            if reverse:
                confidences.append(reverse["confidence"])
                protocols.update(reverse["protocols"])
                observed = max(observed, reverse["observed_at"])
            links.append({
                "a": endpoint_a,
                "b": endpoint_b,
                "bidirectional": reverse is not None,
                "confidence": "high" if all(value == "high" for value in confidences) else "medium",
                "protocols": sorted(protocols),
                "observed_at": observed,
            })
        links.sort(key=lambda row: (
            row["a"]["device"].casefold(), row["a"]["interface"],
            row["b"]["device"].casefold(), row["b"]["interface"],
        ))
        return links

    def get(self, target: str = "all", max_age_minutes: int = 60) -> dict[str, object]:
        if (not isinstance(max_age_minutes, int) or isinstance(max_age_minutes, bool)
                or not 1 <= max_age_minutes <= 10_080):
            raise InventoryError("max_age_minutes must be an integer from 1 through 10080.")
        devices = self.inventory.list()
        if not devices:
            raise InventoryError("No devices are inventoried.")
        selected = None if target.casefold() == "all" else self.inventory.get(target).name
        indexes = self._identity_indexes(devices)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        observations, scans = self.index.topology_snapshot()

        resolved = []
        unresolved = []
        for row in observations:
            resolution = self._resolve_neighbor(row, row["device_name"], indexes)
            item = {
                "source": row["device_name"], "interface": row["interface"],
                "interface_key": row["interface_key"], "neighbor": row["neighbor"],
                "neighbor_address": row.get("neighbor_address", ""),
                "remote_interface": row["remote_interface"], "protocol": row["protocol"],
                "observed_at": row["observed_at"], **resolution,
            }
            if resolution["target"]:
                resolved.append(item)
            else:
                unresolved.append(item)
        links = self._links(self._compact_directed(resolved))

        incomplete = []
        mock_devices = []
        for device in devices:
            adapter = self.capabilities.observation_adapter_for(device)
            supports_neighbors = bool(
                adapter and any(name in adapter.commands for name in ("cdp", "lldp"))
            )
            scan = scans.get(device.name)
            observed = _observed_time(scan.get("observations_at", "")) if scan else None
            stale = observed is None or observed < cutoff
            if scan and scan.get("mock"):
                mock_devices.append(device.name)
            if not supports_neighbors:
                incomplete.append({
                    "device": device.name,
                    "status": "unsupported",
                    "observations_at": "" if not scan else scan.get("observations_at", ""),
                    "error": "No CDP or LLDP collection command is available for this platform.",
                })
            elif not scan or scan["status"] != "success" or stale:
                incomplete.append({
                    "device": device.name,
                    "status": (
                        "not_scanned" if not scan else scan["status"]
                        if scan["status"] != "success" else "stale"
                    ),
                    "observations_at": "" if not scan else scan.get("observations_at", ""),
                    "error": "" if not scan else scan.get("error") or "",
                })

        if selected:
            links = [row for row in links if selected in {row["a"]["device"], row["b"]["device"]}]
            unresolved = [row for row in unresolved if row["source"] == selected]
            related = {selected}
            for link in links:
                related.update((link["a"]["device"], link["b"]["device"]))
            incomplete = [row for row in incomplete if row["device"] in related]
            devices = [device for device in devices if device.name in related]

        degree = {device.name: 0 for device in devices}
        for link in links:
            degree[link["a"]["device"]] = degree.get(link["a"]["device"], 0) + 1
            degree[link["b"]["device"]] = degree.get(link["b"]["device"], 0) + 1
        nodes = [{
            "device": device.name, "hostname": device.device_hostname,
            "device_type": device.device_type, "vendor": device.vendor,
            "platform": device.platform, "location": device.location,
            "street_address": device.street_address, "city": device.city,
            "state": device.state, "zip_code": device.zip_code,
            "country": device.country,
            "degree": degree.get(device.name, 0),
        } for device in devices]
        counts = {
            "nodes": len(nodes), "links": len(links),
            "bidirectional": sum(link["bidirectional"] for link in links),
            "one_sided": sum(not link["bidirectional"] for link in links),
            "unresolved": len(unresolved), "incomplete_devices": len(incomplete),
        }
        complete = not unresolved and not incomplete
        return {
            "status": "success" if complete else "partial",
            "complete": complete, "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "max_age_minutes": max_age_minutes, "counts": counts,
            "nodes": nodes, "links": links, "unresolved_neighbors": unresolved,
            "incomplete_devices": incomplete, "mock": bool(mock_devices),
            "mock_devices": sorted(mock_devices),
        }

    @staticmethod
    def _filter_location(topology: dict[str, object], location: str) -> dict[str, object]:
        term = location.strip().casefold()
        if not term:
            for node in topology["nodes"]:
                node["scope"] = "selected"
            return topology
        if len(term) > 200 or re.search(r"[\x00-\x1f\x7f]", term):
            raise InventoryError("location must be 1-200 printable characters.")
        searchable = ("location", "street_address", "city", "state", "zip_code", "country")
        primary = {
            node["device"] for node in topology["nodes"]
            if any(term in (node.get(field) or "").casefold() for field in searchable)
        }
        if not primary:
            raise InventoryError("No inventory devices match the location filter.")
        links = [
            link for link in topology["links"]
            if link["a"]["device"] in primary or link["b"]["device"] in primary
        ]
        included = set(primary)
        for link in links:
            included.update((link["a"]["device"], link["b"]["device"]))
        nodes = [node for node in topology["nodes"] if node["device"] in included]
        for node in nodes:
            node["scope"] = "selected" if node["device"] in primary else "boundary"
        unresolved = [
            row for row in topology["unresolved_neighbors"] if row["source"] in primary
        ]
        incomplete = [
            row for row in topology["incomplete_devices"] if row["device"] in included
        ]
        counts = {
            "nodes": len(nodes), "links": len(links),
            "bidirectional": sum(link["bidirectional"] for link in links),
            "one_sided": sum(not link["bidirectional"] for link in links),
            "unresolved": len(unresolved), "incomplete_devices": len(incomplete),
        }
        topology.update({
            "nodes": nodes, "links": links, "unresolved_neighbors": unresolved,
            "incomplete_devices": incomplete, "counts": counts,
            "complete": not unresolved and not incomplete,
            "status": "success" if not unresolved and not incomplete else "partial",
        })
        return topology

    def diagram_data(self, target: str = "all", location: str = "",
                     max_age_minutes: int = 60) -> dict[str, object]:
        """Select structured cached topology for presentation."""
        topology = self._filter_location(self.get(target, max_age_minutes), location)
        topology["location_filter"] = location.strip()
        return topology

    def discover(self, target: str = "all", workers: int = 4,
                 max_age_minutes: int = 60) -> dict[str, object]:
        """Refresh only CDP/LLDP observations, then build correlated topology."""
        collection = self.mac_service.scan_neighbors(target, workers)
        topology = self.get(target, max_age_minutes)
        topology["collection_counts"] = collection["counts"]
        topology["collection_status"] = collection["status"]
        return topology
