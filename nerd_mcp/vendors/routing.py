"""Structured routing evidence collection selected by the platform registry."""

from __future__ import annotations

import ipaddress

from ..domain.errors import InventoryError
from ..domain.models import (
    OspfDatabaseCollection,
    OspfDatabaseEvidence,
    RouteEvidence,
)
from ..domain.ports import CommandCollectionPort, InventoryReader
from .commands import command_error
from .registry import require


MAX_TRACE_OUTPUT = 100_000
DATABASE_TYPES = frozenset({"router", "external", "summary"})


def _unicast_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        raise InventoryError("Routing evidence requires a valid IPv4 address.") from None
    if address.version != 4 or address.is_multicast or address.is_unspecified:
        raise InventoryError("Routing evidence requires a unicast IPv4 address.")
    return str(address)


class RoutingEvidenceCollector:
    """Collect and parse route evidence without exposing device text to workflows."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 command_reader: CommandCollectionPort):
        self.inventory = inventory
        self.mock = mock
        self.command_reader = command_reader

    @staticmethod
    def _bounded(outputs: dict[str, str]) -> tuple[dict[str, str], bool]:
        truncated = any(len(output) > MAX_TRACE_OUTPUT for output in outputs.values())
        return {
            key: output[:MAX_TRACE_OUTPUT] for key, output in outputs.items()
        }, truncated

    def collect_route(self, name: str, destination: str) -> RouteEvidence:
        destination = _unicast_ipv4(destination)
        device = self.inventory.get(name)
        platform = require(device, "ospf_trace")
        adapter = platform.routing_collector
        if adapter is None:
            raise InventoryError("Routing evidence is not available for this platform.")
        commands = {
            "route": adapter.ROUTE_COMMAND.format(destination=destination),
            "neighbors": adapter.NEIGHBOR_COMMAND,
        }
        outputs, password = self.command_reader.read_many(
            device.name, commands, 60,
            {
                "route": adapter.MOCK_ROUTE_OUTPUT,
                "neighbors": adapter.MOCK_OSPF_NEIGHBORS,
            },
            platform.driver,
        )
        if password:
            outputs = {
                key: value.replace(password, "[REDACTED]")
                for key, value in outputs.items()
            }
        outputs, truncated = self._bounded(outputs)
        if command_error(outputs["route"]):
            raise InventoryError(
                "The exact-route command was unsupported or not permitted."
            )
        route = adapter.parse_route_detail_model(outputs["route"], destination)
        warnings: list[str] = []
        neighbors = ()
        is_ospf = (
            route.found
            and (
                route.protocol.casefold().startswith("ospf")
                or route.protocol.casefold().startswith("o")
            )
        )
        if is_ospf:
            if command_error(outputs["neighbors"]):
                warnings.append(
                    "The detailed OSPF neighbor command was unsupported or not permitted."
                )
            else:
                neighbors = adapter.parse_ospf_neighbors_model(outputs["neighbors"])
                if not neighbors:
                    warnings.append("No detailed OSPF neighbor rows were recognized.")
        if truncated:
            warnings.insert(0, "Observer command output was truncated.")
        return RouteEvidence(
            route, neighbors, tuple(commands.values()), tuple(warnings), truncated
        )

    def collect_database(
        self, name: str, lsa_type: str, key: str
    ) -> OspfDatabaseCollection:
        if lsa_type not in DATABASE_TYPES:
            raise InventoryError("Unsupported OSPF database evidence type.")
        key = _unicast_ipv4(key)
        device = self.inventory.get(name)
        platform = require(device, "ospf_trace")
        adapter = platform.routing_collector
        if adapter is None:
            raise InventoryError("Routing evidence is not available for this platform.")
        command = adapter.DATABASE_COMMAND.format(kind=lsa_type, key=key)
        output, password = self.command_reader.read(
            device.name, command, 60, adapter.MOCK_OSPF_DATABASE
        )
        if password:
            output = output.replace(password, "[REDACTED]")
        truncated = len(output) > MAX_TRACE_OUTPUT
        output = output[:MAX_TRACE_OUTPUT]
        warnings: list[str] = []
        if command_error(output):
            evidence = OspfDatabaseEvidence(False, (), ())
            warnings.append(
                "The targeted OSPF database command was unsupported or not permitted."
            )
        else:
            evidence = adapter.parse_database_router_model(output, key)
            if not evidence.verified:
                warnings.append(
                    "The targeted OSPF database output did not verify the expected LSA."
                )
        return OspfDatabaseCollection(
            lsa_type, evidence, command, tuple(warnings), truncated
        )
