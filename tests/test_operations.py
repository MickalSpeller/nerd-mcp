"""The shared operation catalog describes every exposed workflow exactly once."""

import asyncio

import pytest

from nerd_mcp.application.operations import (
    MCP_OPERATIONS,
    OPERATIONS,
    OperationEffect,
    OperationSource,
    operation,
    operation_names,
)
from nerd_mcp.inventory import Inventory
from nerd_mcp.server import build_server


def test_catalog_matches_the_mcp_tool_catalog(tmp_path):
    server = build_server(Inventory(tmp_path / "inventory.db"), mock=True)
    tool_names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert tool_names == operation_names(mcp_only=True)
    assert len(MCP_OPERATIONS) == len(tool_names)


def test_mcp_annotations_follow_catalog_effects(tmp_path):
    server = build_server(Inventory(tmp_path / "inventory.db"), mock=True)
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}

    assert tools["get_topology"].annotations.readOnlyHint is True
    assert tools["get_topology"].annotations.openWorldHint is False
    assert tools["get_health"].annotations.readOnlyHint is True
    assert tools["get_health"].annotations.openWorldHint is True
    for name in (
        "refresh_mac_observations", "locate_endpoint",
        "compare_configuration_baseline", "compare_all_configuration_baselines",
        "discover_topology", "trace_mac_path",
    ):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is True


def test_catalog_distinguishes_device_reads_and_local_cache_writes():
    refresh = operation("refresh_mac_observations")
    assert refresh.capability == "mac"
    assert refresh.effects == {
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_CACHE,
    }
    assert refresh.sources == {OperationSource.LIVE_DEVICE}

    cached = operation("get_topology")
    assert cached.effects == {OperationEffect.READ_LOCAL}
    assert cached.sources == {OperationSource.LOCAL_INVENTORY}


def test_conditional_refresh_operations_declare_every_possible_effect():
    expected = {
        OperationEffect.READ_LOCAL,
        OperationEffect.READ_DEVICE,
        OperationEffect.WRITE_CACHE,
    }
    assert operation("locate_endpoint").effects == expected
    assert operation("trace_mac_path").effects == expected


def test_baseline_writes_remain_terminal_only_and_explicit():
    terminal_only = operation_names() - operation_names(mcp_only=True)
    assert {
        "capture_configuration_baseline",
        "refresh_configuration_baselines",
        "remove_configuration_baseline",
    } <= terminal_only
    assert all(
        not definition.mcp_exposed
        for definition in OPERATIONS.values()
        if OperationEffect.WRITE_BASELINE in definition.effects
    )


def test_inventory_writes_are_explicit_terminal_operations():
    assert operation("import_inventory").effects == {OperationEffect.WRITE_INVENTORY}
    assert operation("remove_inventory_device").effects == {OperationEffect.WRITE_INVENTORY}
    assert operation("refresh_inventory").effects == {
        OperationEffect.READ_DEVICE, OperationEffect.WRITE_INVENTORY,
    }
    assert not any(
        definition.mcp_exposed
        for definition in OPERATIONS.values()
        if OperationEffect.WRITE_INVENTORY in definition.effects
    )


def test_catalog_is_immutable_and_rejects_unknown_operations():
    with pytest.raises(TypeError):
        OPERATIONS["new_operation"] = operation("list_devices")
    with pytest.raises(KeyError, match="Unknown application operation"):
        operation("unknown")


def test_execution_provenance_uses_catalog_sources_without_changing_behavior():
    from nerd_mcp.execution import ExecutionTrace

    trace = ExecutionTrace()
    trace.record_tool("search_devices")
    trace.record_tool("get_health")
    trace.record_tool("get_interfaces", mock=True)
    assert trace.data_sources() == ["Local inventory", "Mock device", "Live SSH"]

    unknown = ExecutionTrace()
    unknown.record_tool("future_adapter_operation")
    assert unknown.mcp_tools == ["future_adapter_operation"]
    assert unknown.data_sources() == ["Local"]
