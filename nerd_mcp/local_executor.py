"""In-process execution of the established NERD tool contract.

This adapter gives interactive chat the same application operations without
requiring the MCP SDK or a child Python process.  The stdio MCP adapter remains
available for external clients and compatibility testing.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError, validate

from .application.operations import operation_names
from .application.tool_execution import execute_tool


@dataclass(frozen=True)
class LocalTool:
    name: str
    description: str
    inputSchema: dict[str, Any]


@dataclass(frozen=True)
class LocalToolList:
    tools: tuple[LocalTool, ...]


@dataclass(frozen=True)
class LocalTextContent:
    text: str
    type: str = "text"


@dataclass(frozen=True)
class LocalCallResult:
    structuredContent: dict[str, Any] | None
    content: tuple[LocalTextContent, ...] = ()
    isError: bool = False


def _arguments(*fields: tuple[str, str, tuple[str, ...] | None]) -> dict[str, Any]:
    properties = {}
    required = []
    for name, kind, choices in fields:
        field: dict[str, Any] = {"title": name.replace("_", " ").title(), "type": kind}
        if choices:
            field["enum"] = list(choices)
        properties[name] = field
        required.append(name)
    schema: dict[str, Any] = {"properties": properties}
    if required:
        schema["required"] = required
    schema.update({"title": "Arguments", "type": "object"})
    return schema


S = "string"
I = "integer"
B = "boolean"
ARGUMENTS = {
    "list_devices": _arguments(),
    "get_inventory_device": _arguments(("device", S, None)),
    "search_devices": _arguments(*(
        (name, S, None) for name in (
            "city", "state", "location", "device_type", "hostname", "country",
            "serial_number", "model", "vendor", "platform",
        )
    )),
    "get_device_info": _arguments(("device", S, None)),
    "get_device_facts": _arguments(("device", S, None)),
    "get_interfaces": _arguments(("device", S, None)),
    "get_vlans": _arguments(("device", S, None)),
    "get_routes": _arguments(("device", S, None)),
    "get_neighbors": _arguments(("device", S, None)),
    "get_health": _arguments(("device", S, None)),
    "get_ospf_status": _arguments(("device", S, None)),
    "get_bgp_status": _arguments(("device", S, None)),
    "get_bgp_configuration": _arguments(("device", S, None)),
    "get_bgp_routes": _arguments(("device", S, None)),
    "get_vpn_status": _arguments(("device", S, None)),
    "refresh_mac_observations": _arguments(("target", S, None), ("workers", I, None)),
    "locate_mac": _arguments(("mac_address", S, None), ("max_age_minutes", I, None)),
    "troubleshoot_mac": _arguments(("mac_address", S, None), ("max_age_minutes", I, None)),
    "get_device_macs": _arguments(("device", S, None), ("max_age_minutes", I, None)),
    "get_device_arps": _arguments(("device", S, None), ("max_age_minutes", I, None)),
    "get_interface_macs": _arguments(
        ("device", S, None), ("interface", S, None), ("max_age_minutes", I, None)
    ),
    "locate_endpoint": _arguments(
        ("identifier", S, None), ("source_device", S, None),
        ("max_age_minutes", I, None), ("refresh", B, None), ("workers", I, None),
    ),
    "trace_ospf_route": _arguments(
        ("device", S, None), ("destination", S, None), ("workers", I, None)
    ),
    "get_configuration": _arguments(
        ("device", S, None), ("source", S, ("running", "startup")),
        ("cursor", I, None), ("revision", S, None),
    ),
    "list_configuration_baselines": _arguments(),
    "get_configuration_baseline": _arguments(
        ("device", S, None), ("cursor", I, None), ("revision", S, None)
    ),
    "compare_configuration_baseline": _arguments(
        ("device", S, None), ("cursor", I, None), ("revision", S, None)
    ),
    "compare_all_configuration_baselines": _arguments(("workers", I, None)),
    "get_configuration_baseline_status": _arguments(("max_age_days", I, None)),
    "discover_topology": _arguments(
        ("target", S, None), ("workers", I, None), ("max_age_minutes", I, None)
    ),
    "get_topology": _arguments(("target", S, None), ("max_age_minutes", I, None)),
    "get_topology_diagram": _arguments(
        ("target", S, None), ("location", S, None), ("max_age_minutes", I, None),
        ("format", S, ("text", "mermaid")),
    ),
    "trace_mac_path": _arguments(
        ("mac_address", S, None), ("source_device", S, None),
        ("max_age_minutes", I, None), ("refresh", B, None), ("workers", I, None),
    ),
}

DESCRIPTIONS = {
    "list_devices": "List local device inventory records and identity metadata.",
    "get_inventory_device": "Get one local inventory record without connecting to it.",
    "search_devices": "Search local inventory; pass an empty string for unused filters.",
    "get_device_info": "Read version, hardware, and uptime from a supported device.",
    "get_device_facts": "Read current identity facts without saving the inventory.",
    "get_interfaces": "Read IPv4 interface addresses and operational status.",
    "get_vlans": "Read supported VLAN or logical-interface information.",
    "get_routes": "Read the default IPv4 routing table.",
    "get_neighbors": "Read current CDP or LLDP neighbors.",
    "get_health": "Run fixed health checks and return parsed findings.",
    "get_ospf_status": "Read current OSPF process state and adjacencies.",
    "get_bgp_status": "Read current BGP peer state, duration, router ID, and AS.",
    "get_bgp_configuration": "Read the filtered live BGP configuration for diagnosis.",
    "get_bgp_routes": "Read the current BGP routing table from a supported device.",
    "get_vpn_status": "Read current FortiOS IPsec and SSL-VPN operational status.",
    "refresh_mac_observations": "Refresh MAC, ARP, neighbor, trunk, and interface observations.",
    "locate_mac": "Locate one unicast MAC in the local observation index.",
    "troubleshoot_mac": "Troubleshoot a MAC using cached observations.",
    "get_device_macs": "List the normalized MAC table for one device.",
    "get_device_arps": "List the normalized ARP table for one device.",
    "get_interface_macs": "List learned MAC addresses on one interface.",
    "locate_endpoint": "Locate an endpoint by IPv4 address, MAC, or inventory hostname.",
    "trace_ospf_route": "Trace an exact IPv4 OSPF route and correlate its routers.",
    "get_configuration": "Read one revision-checked sanitized configuration page.",
    "list_configuration_baselines": "List retained sanitized baseline metadata.",
    "get_configuration_baseline": "Read one stored sanitized baseline page.",
    "compare_configuration_baseline": "Compare current configuration with one retained baseline.",
    "compare_all_configuration_baselines": "Compare all inventory devices with retained baselines.",
    "get_configuration_baseline_status": "Read local baseline age and latest drift state.",
    "discover_topology": "Refresh CDP or LLDP observations and correlate topology.",
    "get_topology": "Build topology from cached observations without SSH.",
    "get_topology_diagram": "Render cached topology as text or Mermaid.",
    "trace_mac_path": "Trace a MAC toward its likely access port.",
}

if set(ARGUMENTS) != operation_names(mcp_only=True) or set(DESCRIPTIONS) != set(ARGUMENTS):
    raise RuntimeError("Local tool contracts must match the shared MCP operation catalog.")


class LocalExecutor:
    """Run tool calls against one injected application graph."""

    def __init__(self, application):
        self.application = application
        self._tools = tuple(
            LocalTool(
                name, DESCRIPTIONS[name],
                {**ARGUMENTS[name], "title": f"{name}Arguments"},
            )
            for name in ARGUMENTS
        )

    async def list_tools(self) -> LocalToolList:
        return LocalToolList(self._tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> LocalCallResult:
        schema = {
            **ARGUMENTS.get(name, {}),
            "title": f"{name}Arguments",
            "additionalProperties": False,
        }
        if name not in ARGUMENTS:
            return self._error("Unknown tool.")
        try:
            validate(arguments, schema)
            result = await asyncio.to_thread(
                execute_tool, self.application, name, arguments
            )
            return LocalCallResult(structuredContent=result)
        except ValidationError:
            return self._error("Invalid tool arguments.")
        except Exception:
            return self._error("Tool request failed.")

    @staticmethod
    def _error(message: str) -> LocalCallResult:
        return LocalCallResult(
            structuredContent={"error": message},
            content=(LocalTextContent(json.dumps({"error": message})),),
            isError=True,
        )
