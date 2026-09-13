"""End-to-end endpoint path inference from current MAC and topology observations."""

from __future__ import annotations

from ..domain.errors import InventoryError
from ..domain.ports import InventoryReader
from ..domain.normalization import interface_key, normalize_mac


class MacPathWorkflow:
    """Path inference workflow with upstream services supplied by its caller."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 mac_service, topology_service):
        self.inventory = inventory
        self.mock = mock
        self.mac_service = mac_service
        self.topology_service = topology_service

    @staticmethod
    def _link_lookup(links: list[dict]) -> dict[tuple[str, str], list[dict]]:
        lookup: dict[tuple[str, str], list[dict]] = {}
        for link in links:
            for local, remote in ((link["a"], link["b"]), (link["b"], link["a"])):
                if not local["interface"]:
                    continue
                lookup.setdefault(
                    (local["device"], interface_key(local["interface"])), []
                ).append({
                    "from_device": local["device"],
                    "from_interface": local["interface"],
                    "to_device": remote["device"],
                    "to_interface": remote["interface"],
                    "bidirectional": link["bidirectional"],
                    "confidence": link["confidence"],
                    "protocols": link["protocols"],
                    "observed_at": link["observed_at"],
                })
        return lookup

    @staticmethod
    def _enumerate_paths(adjacency: dict[str, list[dict]], start: str, target: str,
                         limit: int = 64) -> tuple[list[list[dict]], bool]:
        paths: list[list[dict]] = []
        cycle = False

        def walk(device: str, hops: list[dict], visited: set[str]) -> None:
            nonlocal cycle
            if len(paths) >= limit:
                return
            if device == target:
                paths.append(list(hops))
                return
            for edge in adjacency.get(device, []):
                if edge["to_device"] in visited:
                    cycle = True
                    continue
                walk(
                    edge["to_device"], hops + [edge],
                    visited | {edge["to_device"]},
                )

        walk(start, [], {start})
        return paths, cycle

    @staticmethod
    def _deduplicate_edges(edges: list[dict]) -> list[dict]:
        selected: dict[tuple[str, str, str], dict] = {}
        for edge in edges:
            key = (edge["from_device"], edge["from_interface"], edge["to_device"])
            previous = selected.get(key)
            score = int(edge["bidirectional"]) + int(edge["confidence"] == "high")
            previous_score = (
                -1 if previous is None
                else int(previous["bidirectional"]) + int(previous["confidence"] == "high")
            )
            if score > previous_score:
                selected[key] = edge
        return sorted(selected.values(), key=lambda row: (
            row["from_device"].casefold(), row["to_device"].casefold(),
            row["from_interface"], row["to_interface"],
        ))

    def trace(self, mac_address: str, source_device: str = "",
              max_age_minutes: int = 15, refresh: bool = False,
              workers: int = 4) -> dict[str, object]:
        mac = normalize_mac(mac_address)
        if not isinstance(refresh, bool):
            raise InventoryError("refresh must be true or false.")
        if (not isinstance(workers, int) or isinstance(workers, bool)
                or not 1 <= workers <= 16):
            raise InventoryError("workers must be an integer from 1 through 16.")
        source = self.inventory.get(source_device).name if source_device.strip() else ""
        if refresh:
            collection = self.mac_service.scan("all", workers)
            topology = self.topology_service.get("all", max_age_minutes)
        else:
            topology = self.topology_service.get("all", max_age_minutes)
        location = self.mac_service.locate(mac, max_age_minutes)
        matches = location["matches"]
        access = [
            row for row in matches
            if row["role"] == "access" and row["entry_type"] == "dynamic"
        ]
        endpoint = access[0] if len(access) == 1 else location.get("likely_endpoint")
        endpoint_is_access = bool(endpoint and endpoint in access)
        if endpoint_is_access:
            endpoint = {**endpoint, "ip_addresses": location["ip_addresses"]}
        endpoint_device = endpoint["device_name"] if endpoint_is_access else ""

        link_lookup = self._link_lookup(topology["links"])
        unresolved_by_port: dict[tuple[str, str], list[dict]] = {}
        for row in topology["unresolved_neighbors"]:
            unresolved_by_port.setdefault(
                (row["source"], row["interface_key"]), []
            ).append(row)

        edges = []
        unresolved_hops = []
        for match in matches:
            if match["role"] != "uplink":
                continue
            key = (match["device_name"], match["interface_key"])
            candidates = link_lookup.get(key, [])
            if candidates:
                edges.extend(candidates)
                continue
            neighbor_rows = unresolved_by_port.get(key, [])
            unresolved_hops.append({
                "device": match["device_name"], "interface": match["interface"],
                "vlan": match["vlan"],
                "neighbors": [row["neighbor"] for row in neighbor_rows],
                "neighbor_addresses": [
                    row["neighbor_address"] for row in neighbor_rows if row["neighbor_address"]
                ],
                "reason": (
                    "The MAC is learned toward an unresolved CDP/LLDP neighbor."
                    if neighbor_rows else
                    "The MAC is learned on an uplink with no correlated topology link."
                ),
            })
        edges = self._deduplicate_edges(edges)
        adjacency: dict[str, list[dict]] = {}
        for edge in edges:
            adjacency.setdefault(edge["from_device"], []).append(edge)

        possible_paths: list[list[dict]] = []
        cycle = False
        inferred_source = source
        if endpoint_device:
            if source:
                possible_paths, cycle = self._enumerate_paths(
                    adjacency, source, endpoint_device
                )
                possible_paths.sort(key=lambda path: (len(path), str(path)))
            else:
                reachable = {endpoint_device}
                changed = True
                while changed:
                    changed = False
                    for edge in edges:
                        if edge["to_device"] in reachable and edge["from_device"] not in reachable:
                            reachable.add(edge["from_device"])
                            changed = True
                relevant_edges = [
                    edge for edge in edges
                    if edge["from_device"] in reachable and edge["to_device"] in reachable
                ]
                incoming = {device: 0 for device in reachable}
                for edge in relevant_edges:
                    incoming[edge["to_device"]] = incoming.get(edge["to_device"], 0) + 1
                roots = sorted(
                    (device for device in reachable
                     if device != endpoint_device and incoming.get(device, 0) == 0),
                    key=str.casefold,
                )
                if not roots and relevant_edges:
                    roots = sorted(reachable - {endpoint_device}, key=str.casefold)
                for root in roots:
                    found, has_cycle = self._enumerate_paths(
                        adjacency, root, endpoint_device
                    )
                    possible_paths.extend(found)
                    cycle = cycle or has_cycle
                possible_paths.sort(key=lambda path: (-len(path), str(path)))
                if possible_paths:
                    inferred_source = possible_paths[0][0]["from_device"]

        primary = possible_paths[0] if possible_paths else []
        path_devices = []
        if primary:
            path_devices = [primary[0]["from_device"]] + [edge["to_device"] for edge in primary]
        elif endpoint_device:
            path_devices = [endpoint_device]
        relevant_devices = {
            row["device_name"] for row in matches
        } | set(path_devices) | ({source} if source else set())
        coverage: dict[tuple[str, str], dict] = {}
        for origin, rows in (("mac", location["incomplete_devices"]),
                             ("topology", topology["incomplete_devices"])):
            for row in rows:
                if row["device"] in relevant_devices:
                    coverage[(origin, row["device"])] = {
                        "source": origin, **row,
                    }
        incomplete = list(coverage.values())

        warnings = []
        if not matches:
            warnings.append("The MAC was not found in the current observation index.")
        elif not endpoint_is_access:
            warnings.append("No unique dynamic access-port endpoint could be selected.")
        if len(access) > 1:
            warnings.append("Multiple dynamic access-port candidates make the endpoint ambiguous.")
        if endpoint_is_access and source and source != endpoint_device and not primary:
            warnings.append(f"No observed MAC path connects {source} to {endpoint_device}.")
        if endpoint_is_access and not source and not primary:
            warnings.append("The access port was found, but no upstream topology path was observed.")
        if len(possible_paths) > 1:
            warnings.append("Multiple observed paths reach the selected endpoint; the primary path is not unique.")
        if cycle:
            warnings.append("A cycle exists in the MAC-bearing topology observations.")
        if unresolved_hops:
            warnings.append("One or more MAC-bearing uplinks could not be mapped to an inventory link.")
        if incomplete:
            warnings.append("One or more devices relevant to the path have incomplete or stale observations.")
        if any(not edge["bidirectional"] for edge in primary):
            warnings.append("The selected path contains a one-sided topology link.")

        path_found = bool(primary) or bool(source and source == endpoint_device)
        complete = bool(
            endpoint_is_access and path_found and len(access) == 1
            and len(possible_paths) <= 1 and not cycle and not unresolved_hops
            and not incomplete
        )
        if not matches:
            confidence = "none"
        elif not endpoint_is_access or not path_found:
            confidence = "low"
        elif complete and all(
            edge["bidirectional"] and edge["confidence"] == "high" for edge in primary
        ):
            confidence = "high" if source else "medium"
        else:
            confidence = "medium"

        alternatives = []
        for path in possible_paths[1:10]:
            alternatives.append(
                [path[0]["from_device"]] + [edge["to_device"] for edge in path]
            )
        result = {
            "status": "success" if complete else "partial",
            "complete": complete, "found": bool(matches), "path_found": path_found,
            "mac": mac, "requested_source": source, "source_device": inferred_source,
            "endpoint": endpoint if endpoint_is_access else None,
            "confidence": confidence, "path_devices": path_devices,
            "hops": [{"sequence": index, **edge} for index, edge in enumerate(primary, 1)],
            "alternative_paths": alternatives, "unresolved_hops": unresolved_hops,
            "incomplete_devices": incomplete, "warnings": warnings,
            "max_age_minutes": max_age_minutes, "refreshed": refresh,
            "mock": bool(location.get("mock") or topology.get("mock")),
        }
        if refresh:
            result["collection_counts"] = collection.get("counts", {})
            result["collection_status"] = collection.get("status", "")
        return result
