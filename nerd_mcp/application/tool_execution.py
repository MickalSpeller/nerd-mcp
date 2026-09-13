"""Adapter-neutral dispatch for the established MCP tool operations."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any


def execute_tool(application, name: str,
                 arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke one named operation on an injected application graph."""
    app = application
    if name == "list_devices":
        return {
            "devices": [asdict(row) for row in app.inventory.list()],
            "mock": app.mock,
        }
    if name == "get_inventory_device":
        return {
            "device": asdict(app.inventory.get(arguments["device"])),
            "mock": app.mock,
        }
    if name == "search_devices":
        matches = app.inventory.search(**arguments)
        return {
            "devices": [asdict(row) for row in matches],
            "count": len(matches),
            "mock": app.mock,
        }
    if name in {
        "get_device_info", "get_interfaces", "get_vlans", "get_routes",
        "get_neighbors",
    }:
        return app.network.inspect(name, arguments["device"])
    if name == "get_device_facts":
        return app.network.discover_inventory(arguments["device"])
    if name == "get_health":
        return app.network.health(arguments["device"])
    if name == "get_ospf_status":
        return app.network.ospf_status(arguments["device"])
    if name == "get_bgp_status":
        return app.network.bgp_status(arguments["device"])
    if name == "get_bgp_configuration":
        return app.network.bgp_configuration(arguments["device"])
    if name == "get_bgp_routes":
        return app.network.bgp_routes(arguments["device"])
    if name == "get_vpn_status":
        return app.network.vpn_status(arguments["device"])
    if name == "refresh_mac_observations":
        return app.mac.scan(arguments["target"], arguments["workers"])
    if name == "locate_mac":
        return app.mac.locate(
            arguments["mac_address"], arguments["max_age_minutes"]
        )
    if name == "troubleshoot_mac":
        return app.mac.troubleshoot(
            arguments["mac_address"], arguments["max_age_minutes"]
        )
    if name == "get_device_macs":
        return app.mac.device_macs(
            arguments["device"], arguments["max_age_minutes"]
        )
    if name == "get_device_arps":
        return app.mac.device_arps(
            arguments["device"], arguments["max_age_minutes"]
        )
    if name == "get_interface_macs":
        return app.mac.interface_macs(
            arguments["device"], arguments["interface"],
            arguments["max_age_minutes"],
        )
    if name == "locate_endpoint":
        return app.endpoints.locate(**arguments)
    if name == "trace_ospf_route":
        return app.routing.trace(**arguments)
    if name == "get_configuration":
        return app.network.get_configuration(
            arguments["device"], arguments["source"], arguments["cursor"],
            arguments["revision"],
        )
    if name == "list_configuration_baselines":
        return app.baselines.list()
    if name == "get_configuration_baseline":
        return app.baselines.get_page(**arguments)
    if name == "compare_configuration_baseline":
        return app.baselines.compare_page(**arguments)
    if name == "compare_all_configuration_baselines":
        return app.baselines.compare_all(arguments["workers"])
    if name == "get_configuration_baseline_status":
        return app.baselines.status(arguments["max_age_days"])
    if name == "discover_topology":
        return app.topology.discover(**arguments)
    if name == "get_topology":
        return app.topology.get(**arguments)
    if name == "get_topology_diagram":
        return app.topology.diagram(
            arguments["target"], arguments["location"],
            arguments["max_age_minutes"], arguments["format"],
        )
    if name == "trace_mac_path":
        return app.mac_paths.trace(**arguments)
    raise KeyError(f"Unknown application tool: {name}")
