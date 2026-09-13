"""Shared operation capabilities, possible effects, and provenance metadata."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class OperationEffect(StrEnum):
    READ_LOCAL = "read_local"
    READ_DEVICE = "read_device"
    WRITE_CACHE = "write_cache"
    WRITE_INVENTORY = "write_inventory"
    WRITE_BASELINE = "write_baseline"
    WRITE_DEVICE = "write_device"
    SAVE_DEVICE = "save_device"
    WRITE_AUDIT = "write_audit"


class OperationSource(StrEnum):
    LOCAL_INVENTORY = "local_inventory"
    LIVE_DEVICE = "live_device"


@dataclass(frozen=True)
class OperationDefinition:
    """Static metadata for one application operation.

    Effects describe everything a valid invocation may do. Sources retain the
    established execution-footer behavior and describe the primary reported data
    source rather than every dependency consulted by an operation.
    """

    name: str
    capability: str
    effects: frozenset[OperationEffect]
    sources: frozenset[OperationSource]
    mcp_exposed: bool = False

    def has_effect(self, effect: OperationEffect) -> bool:
        return effect in self.effects


def _definition(name: str, capability: str, *effects: OperationEffect,
                sources: tuple[OperationSource, ...] = (),
                mcp: bool = True) -> OperationDefinition:
    return OperationDefinition(
        name=name, capability=capability, effects=frozenset(effects),
        sources=frozenset(sources), mcp_exposed=mcp,
    )


LOCAL = (OperationSource.LOCAL_INVENTORY,)
LIVE = (OperationSource.LIVE_DEVICE,)

_DEFINITIONS = (
    _definition("list_devices", "inventory", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_inventory_device", "inventory", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("search_devices", "inventory", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_device_info", "inspection", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_device_facts", "facts", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_interfaces", "interfaces", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_vlans", "inspection", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_routes", "inspection", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_neighbors", "inspection", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_health", "health", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_ospf_status", "ospf", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_bgp_status", "bgp", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_bgp_configuration", "bgp", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_bgp_routes", "bgp", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_vpn_status", "vpn", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition(
        "refresh_mac_observations", "mac", OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_CACHE, sources=LIVE,
    ),
    _definition("locate_mac", "mac", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("troubleshoot_mac", "mac", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_device_macs", "mac", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_device_arps", "mac", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_interface_macs", "mac", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition(
        "locate_endpoint", "endpoint", OperationEffect.READ_LOCAL,
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_CACHE, sources=LOCAL,
    ),
    _definition("trace_ospf_route", "ospf_trace", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition("get_configuration", "configuration", OperationEffect.READ_DEVICE, sources=LIVE),
    _definition(
        "list_configuration_baselines", "configuration_baselines",
        OperationEffect.READ_LOCAL, sources=LOCAL,
    ),
    _definition(
        "get_configuration_baseline", "configuration_baselines",
        OperationEffect.READ_LOCAL, sources=LOCAL,
    ),
    _definition(
        "compare_configuration_baseline", "configuration_baselines",
        OperationEffect.READ_LOCAL, OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_CACHE, sources=LIVE,
    ),
    _definition(
        "compare_all_configuration_baselines", "configuration_baselines",
        OperationEffect.READ_LOCAL, OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_CACHE, sources=LIVE,
    ),
    _definition(
        "get_configuration_baseline_status", "configuration_baselines",
        OperationEffect.READ_LOCAL, sources=LOCAL,
    ),
    _definition(
        "discover_topology", "topology", OperationEffect.READ_LOCAL,
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_CACHE, sources=LIVE,
    ),
    _definition("get_topology", "topology", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition("get_topology_diagram", "topology", OperationEffect.READ_LOCAL, sources=LOCAL),
    _definition(
        "trace_mac_path", "mac_path", OperationEffect.READ_LOCAL,
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_CACHE, sources=LOCAL,
    ),
    # Terminal-only application workflows use the same vocabulary.
    _definition(
        "import_inventory", "inventory", OperationEffect.WRITE_INVENTORY,
        sources=LOCAL, mcp=False,
    ),
    _definition(
        "remove_inventory_device", "inventory", OperationEffect.WRITE_INVENTORY,
        sources=LOCAL, mcp=False,
    ),
    _definition(
        "refresh_inventory", "facts", OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_INVENTORY, sources=LIVE, mcp=False,
    ),
    _definition(
        "check_fleet_health", "health", OperationEffect.READ_DEVICE,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "capture_configuration_baseline", "configuration_baselines",
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_BASELINE,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "refresh_configuration_baselines", "configuration_baselines",
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_BASELINE,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "remove_configuration_baseline", "configuration_baselines",
        OperationEffect.WRITE_BASELINE, sources=LOCAL, mcp=False,
    ),
    _definition(
        "prepare_configuration_change", "configuration_changes",
        OperationEffect.READ_LOCAL, OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_AUDIT,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "diagnose_and_prepare_change", "configuration_changes",
        OperationEffect.READ_LOCAL, OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_AUDIT, sources=LIVE, mcp=False,
    ),
    _definition(
        "apply_configuration_change", "configuration_changes",
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_DEVICE, OperationEffect.WRITE_AUDIT,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "save_configuration_change", "configuration_changes",
        OperationEffect.READ_DEVICE, OperationEffect.SAVE_DEVICE, OperationEffect.WRITE_AUDIT,
        sources=LIVE, mcp=False,
    ),
    _definition(
        "purge_configuration_changes", "configuration_changes",
        OperationEffect.WRITE_AUDIT, sources=LOCAL, mcp=False,
    ),
)

if len({definition.name for definition in _DEFINITIONS}) != len(_DEFINITIONS):
    raise RuntimeError("Operation names must be unique.")

OPERATIONS = MappingProxyType({definition.name: definition for definition in _DEFINITIONS})
MCP_OPERATIONS = tuple(
    definition for definition in _DEFINITIONS if definition.mcp_exposed
)


def operation(name: str) -> OperationDefinition:
    try:
        return OPERATIONS[name]
    except KeyError as exc:
        raise KeyError(f"Unknown application operation: {name}") from exc


def operation_names(*, source: OperationSource | None = None,
                    mcp_only: bool = False) -> frozenset[str]:
    definitions = MCP_OPERATIONS if mcp_only else _DEFINITIONS
    return frozenset(
        definition.name for definition in definitions
        if source is None or source in definition.sources
    )
