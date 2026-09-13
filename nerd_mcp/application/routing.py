"""Read-only OSPF route tracing and inventory address correlation."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ..domain.errors import InventoryError
from ..domain.ports import (
    InventoryReader,
    NetworkPort,
    RoutingEvidencePort,
)
from .serialization import (
    ospf_database_legacy,
    ospf_neighbors_legacy,
    route_detail_legacy,
)

def normalize_destination(value: str) -> str:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        raise InventoryError("Destination must be one IPv4 address, such as 2.2.2.2.") from None
    if address.version != 4 or address.is_multicast or address.is_unspecified:
        raise InventoryError("Destination must be an individual unicast IPv4 address.")
    return str(address)




def _valid_ipv4_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return str(address) if address.version == 4 else ""


class RouteTracingWorkflow:
    """Route tracing workflow with collection dependencies supplied by its caller."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 network: NetworkPort,
                 routing_collector: RoutingEvidencePort, capability_provider,
                 error_mapper):
        self.inventory = inventory
        self.mock = mock
        self.network = network
        self.routing_collector = routing_collector
        self.capabilities = capability_provider
        self.error_mapper = error_mapper
        self.command_reader = getattr(routing_collector, "command_reader", None)

    def _interface_owners(self, addresses: set[str], workers: int) -> tuple[dict[str, list[dict]], list[dict]]:
        owners: dict[str, list[dict]] = {address: [] for address in addresses}
        devices = [
            device for device in self.inventory.list()
            if self.capabilities.supports(device, "ospf_trace")
        ]
        checks: list[dict] = []

        for device in devices:
            if device.host in owners:
                owners[device.host].append({
                    "device": device.name,
                    "address": device.host,
                    "interface": "inventory host",
                    "source": "inventory_host",
                    "status": "",
                    "protocol": "",
                })

        if devices:
            with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
                pending = {
                    pool.submit(self.network.collect_interfaces, device.name): device.name
                    for device in devices
                }
                for future in as_completed(pending):
                    name = pending[future]
                    result = future.result()
                    found = []
                    if result.status in {"success", "partial"}:
                        for row in result.data or ():
                            if row.address in owners:
                                found.append(row.address)
                                owners[row.address].append({
                                    "device": name,
                                    "address": row.address,
                                    "interface": row.name,
                                    "source": "live_interface",
                                    "status": row.status or "",
                                    "protocol": row.protocol or "",
                                })
                    checks.append({
                        "device": name,
                        "status": result.status,
                        "error": (
                            "Interface output was truncated before all addresses could be checked."
                            if result.truncated else result.error or (" ".join(result.warnings) or None)
                        ),
                        "matched_addresses": sorted(set(found), key=ipaddress.ip_address),
                    })
        for address in owners:
            unique = {}
            for owner in owners[address]:
                key = (owner["device"], owner["address"], owner["interface"], owner["source"])
                unique[key] = owner
            owners[address] = sorted(unique.values(), key=lambda row: (row["device"], row["interface"]))
        checks.sort(key=lambda row: row["device"])
        return owners, checks

    def trace(self, device: str, destination: str, workers: int = 4) -> dict[str, object]:
        timestamp = datetime.now(timezone.utc).isoformat()
        result: dict[str, object] = {
            "device": device,
            "destination": destination,
            "timestamp": timestamp,
            "status": "error",
            "complete": False,
            "route_found": False,
            "is_ospf": False,
            "route": {},
            "next_hops": [],
            "ospf_neighbors": [],
            "route_source_router_ids": [],
            "advertising_router_id": None,
            "advertising_device": None,
            "confidence": "none",
            "database": None,
            "inventory_checks": [],
            "incomplete_devices": [],
            "commands": [],
            "evidence": [],
            "truncated": False,
            "warnings": [],
            "error": None,
            "mock": self.mock,
        }
        try:
            destination = normalize_destination(destination)
            result["destination"] = destination
            if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
                raise InventoryError("workers must be an integer from 1 through 16.")
            observer = self.inventory.get(device)
            if not self.capabilities.supports(observer, "ospf_trace"):
                raise InventoryError("OSPF route tracing currently supports Cisco IOS/IOS-XE inventory records only.")
            collected = self.routing_collector.collect_route(
                observer.name, destination
            )
            result["commands"] = list(collected.commands)
            result["truncated"] = collected.truncated
            result["warnings"].extend(collected.warnings)
            route = route_detail_legacy(collected.route)
            result["route"] = route
            result["route_found"] = route["found"]
            result["evidence"] = route["evidence"]
            if not route["found"]:
                result.update({"status": "success", "complete": not result["truncated"]})
                return result

            protocol = str(route["protocol"]).casefold()
            result["is_ospf"] = protocol.startswith("ospf") or protocol.startswith("o")
            if not result["is_ospf"]:
                result.update({"status": "success", "complete": not result["truncated"], "confidence": "high"})
                return result

            neighbors = ospf_neighbors_legacy(collected.neighbors)
            result["ospf_neighbors"] = neighbors
            source_ids = list(route["route_source_router_ids"])
            result["route_source_router_ids"] = source_ids

            database = None
            route_type = str(route.get("route_type") or "").casefold()
            prefix_id = _valid_ipv4_address(str(route.get("prefix") or "").split("/")[0])
            database_kind = ""  # pragma: allowlist secret (OSPF database selector)
            database_key = ""  # pragma: allowlist secret (OSPF database selector)
            if "extern" in route_type or "nssa" in route_type:
                database_kind, database_key = "external", prefix_id  # pragma: allowlist secret
            elif "inter area" in route_type or "summary" in route_type:
                database_kind, database_key = "summary", prefix_id  # pragma: allowlist secret
            elif source_ids:
                database_kind, database_key = (  # pragma: allowlist secret
                    "router", normalize_destination(source_ids[0])
                )
            if database_kind and database_key:
                collected_database = self.routing_collector.collect_database(
                    observer.name, database_kind, database_key
                )
                result["commands"].append(collected_database.command)
                result["truncated"] = (
                    result["truncated"] or collected_database.truncated
                )
                result["warnings"].extend(collected_database.warnings)
                database = ospf_database_legacy(collected_database.evidence)
                database["lsa_type"] = collected_database.lsa_type
            elif not source_ids:
                result["warnings"].append("The route output did not identify an OSPF route-source router ID.")
            result["database"] = database

            addresses = {hop["address"] for hop in route["next_hops"]}
            addresses.update(source_ids)
            addresses.update(row["router_id"] for row in neighbors)
            if database:
                addresses.update(database["advertising_router_ids"])
            owners, checks = self._interface_owners(addresses, workers)
            result["inventory_checks"] = checks
            result["incomplete_devices"] = [
                {"device": row["device"], "error": row["error"]}
                for row in checks if row["status"] != "success"
            ]

            neighbor_by_address = {row["address"]: row for row in neighbors}
            traced_hops = []
            for hop in route["next_hops"]:
                neighbor = neighbor_by_address.get(hop["address"])
                router_id = (neighbor or {}).get("router_id") or hop.get("route_source_router_id")
                candidates = list(owners.get(hop["address"], []))
                if router_id:
                    candidates.extend(owners.get(str(router_id), []))
                unique_devices = sorted({row["device"] for row in candidates})
                traced_hops.append({
                    **hop,
                    "neighbor_router_id": router_id,
                    "neighbor_state": None if not neighbor else neighbor.get("state"),
                    "neighbor_area": None if not neighbor else neighbor.get("area"),
                    "owners": candidates,
                    "device": unique_devices[0] if len(unique_devices) == 1 else None,
                })
            result["next_hops"] = traced_hops

            database_advertisers = [] if not database else database["advertising_router_ids"]
            advertising_router_id = (
                database_advertisers[0] if len(database_advertisers) == 1
                else source_ids[0] if len(source_ids) == 1
                else None
            )
            result["advertising_router_id"] = advertising_router_id
            advertising_candidates = [] if not advertising_router_id else list(owners.get(advertising_router_id, []))
            for hop in traced_hops:
                if hop["neighbor_router_id"] == advertising_router_id:
                    advertising_candidates.extend(hop["owners"])
            advertising_devices = sorted({row["device"] for row in advertising_candidates})
            result["advertising_device"] = advertising_devices[0] if len(advertising_devices) == 1 else None
            if not result["advertising_device"]:
                result["warnings"].append("The advertising router could not be uniquely mapped to inventory.")

            mapping_complete = not result["incomplete_devices"]
            database_verified = bool(database and database.get("verified"))
            result["complete"] = bool(
                neighbors and advertising_router_id and result["advertising_device"]
                and mapping_complete and database_verified and not result["truncated"]
            )
            if result["complete"]:
                confidence = "high"
            elif result["advertising_device"] or any(hop["device"] for hop in traced_hops):
                confidence = "medium"
            else:
                confidence = "low"
            result.update({"status": "success", "confidence": confidence})
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
        return result
