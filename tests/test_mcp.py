from types import SimpleNamespace
from unittest.mock import AsyncMock

from nerd_mcp.chat import Chat, local_session
from nerd_mcp.application.operations import MCP_OPERATIONS, OperationEffect
from nerd_mcp.inventory import Inventory
from nerd_mcp.network import COMMANDS
from nerd_mcp.server import SERVER_INSTRUCTIONS
from nerd_mcp.snapshots import ConfigurationBaselines


def test_mcp_catalog_never_exposes_device_writes():
    assert MCP_OPERATIONS
    assert all(OperationEffect.WRITE_DEVICE not in item.effects for item in MCP_OPERATIONS)
    assert all(OperationEffect.SAVE_DEVICE not in item.effects for item in MCP_OPERATIONS)


def test_server_about_description_is_vendor_agnostic():
    assert "Network Engineering Reconnaissance & Discovery" in SERVER_INSTRUCTIONS
    assert "vendor-agnostic" in SERVER_INSTRUCTIONS
    assert "General live inspection supports Cisco IOS/IOS-XE and Fortinet FortiOS" in SERVER_INSTRUCTIONS
    assert "MAC observation adapters support" in SERVER_INSTRUCTIONS


async def test_real_stdio_subprocess_mock_devices(tmp_path):
    path = tmp_path / "devices.csv"
    path.write_text("name,host\ncore,192.0.2.1\n")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(path)
    assert ConfigurationBaselines(inventory, mock=True).capture("core")["status"] == "success"
    async with local_session(inventory.path, mock=True) as session:
        tools = (await session.list_tools()).tools
        assert {tool.name for tool in tools} == {
            "list_devices", "get_inventory_device", "search_devices",
            *COMMANDS, "get_device_facts", "get_configuration", "get_health", "get_ospf_status",
            "get_bgp_status", "get_bgp_configuration", "get_bgp_routes",
            "get_vpn_status",
            "refresh_mac_observations", "locate_mac", "troubleshoot_mac", "get_device_macs",
            "get_device_arps", "get_interface_macs",
            "locate_endpoint",
            "trace_ospf_route",
            "list_configuration_baselines", "get_configuration_baseline",
            "compare_configuration_baseline",
            "compare_all_configuration_baselines",
            "get_configuration_baseline_status",
            "discover_topology", "get_topology", "get_topology_diagram",
            "trace_mac_path",
        }
        devices = await session.call_tool("list_devices", {})
        assert devices.structuredContent["devices"][0]["name"] == "core"
        search = await session.call_tool("search_devices", {
            "city": "", "state": "", "location": "", "device_type": "",
            "hostname": "core", "country": "", "serial_number": "", "model": "",
            "vendor": "", "platform": "",
        })
        assert search.structuredContent["count"] == 1
        for operation in COMMANDS:
            result = await session.call_tool(operation, {"device": "core"})
            assert not result.isError
            assert result.structuredContent["status"] == "success"
            assert result.structuredContent["mock"] is True
        bad = await session.call_tool("get_interfaces", {"device": "core;reload"})
        assert bad.structuredContent["status"] == "error"
        config = await session.call_tool("get_configuration", {
            "device": "core", "source": "running", "cursor": 0, "revision": ""
        })
        assert not config.isError
        assert config.structuredContent["status"] == "success"
        assert config.structuredContent["complete"] is True
        assert "mock-enable-secret" not in config.structuredContent["output"]
        config_tool = next(tool for tool in tools if tool.name == "get_configuration")
        assert set(config_tool.inputSchema["required"]) == {"device", "source", "cursor", "revision"}
        health = await session.call_tool("get_health", {"device": "core"})
        assert not health.isError
        assert health.structuredContent["status"] == "success"
        assert health.structuredContent["overall"] == "healthy"
        ospf = await session.call_tool("get_ospf_status", {"device": "core"})
        assert not ospf.isError
        assert ospf.structuredContent["status"] == "success"
        assert ospf.structuredContent["running"] is True
        assert ospf.structuredContent["neighbor_count"] == 1
        bgp = await session.call_tool("get_bgp_status", {"device": "core"})
        assert not bgp.isError
        assert bgp.structuredContent["router_id"] == "1.1.1.1"
        assert bgp.structuredContent["neighbors"][0]["up_down"] == "1d02h"
        facts = await session.call_tool("get_device_facts", {"device": "core"})
        assert not facts.isError
        assert facts.structuredContent["status"] == "success"
        assert facts.structuredContent["facts"]["serial_number"] == "FOC1234ABCD"
        assert "record" not in facts.structuredContent
        assert inventory.get("core").serial_number == ""
        refresh = await session.call_tool("refresh_mac_observations", {
            "target": "core", "workers": 1,
        })
        assert not refresh.isError
        assert refresh.structuredContent["status"] == "success"
        located = await session.call_tool("locate_mac", {
            "mac_address": "0011.2233.4455", "max_age_minutes": 15,
        })
        assert not located.isError
        assert located.structuredContent["likely_endpoint"]["interface"] == "Gi1/0/18"
        trouble = await session.call_tool("troubleshoot_mac", {
            "mac_address": "00:11:22:33:44:55", "max_age_minutes": 15,
        })
        assert not trouble.isError
        assert trouble.structuredContent["healthy"] is True
        table = await session.call_tool("get_device_macs", {
            "device": "core", "max_age_minutes": 15,
        })
        assert not table.isError
        assert table.structuredContent["complete"] is True
        assert table.structuredContent["count"] >= 1
        assert table.structuredContent["observations"][0]["interface"]
        arp_table = await session.call_tool("get_device_arps", {
            "device": "core", "max_age_minutes": 15,
        })
        assert not arp_table.isError
        assert arp_table.structuredContent["complete"] is True
        assert arp_table.structuredContent["observations"][0] == {
            "ip": "10.20.0.45",
            "mac": "00:11:22:33:44:55",
            "interface": "Vlan20",
            "vrf": "default",
            "observed_at": arp_table.structuredContent["observations_at"],
        }
        port = await session.call_tool("get_interface_macs", {
            "device": "core", "interface": "GigabitEthernet1/0/18", "max_age_minutes": 15,
        })
        assert not port.isError
        assert port.structuredContent["observations"][0]["mac"] == "00:11:22:33:44:55"
        endpoint = await session.call_tool("locate_endpoint", {
            "identifier": "10.20.0.45", "source_device": "",
            "max_age_minutes": 15, "refresh": False, "workers": 1,
        })
        assert not endpoint.isError
        assert endpoint.structuredContent["found"] is True
        assert endpoint.structuredContent["endpoints"][0]["endpoint"]["interface"] == "Gi1/0/18"
        route = await session.call_tool("trace_ospf_route", {
            "device": "core", "destination": "2.2.2.2", "workers": 1,
        })
        assert not route.isError
        assert route.structuredContent["route_found"] is True
        assert route.structuredContent["advertising_router_id"] == "2.2.2.2"
        baseline_list = await session.call_tool("list_configuration_baselines", {})
        assert baseline_list.structuredContent["baselines"][0]["device"] == "core"
        baseline = await session.call_tool("get_configuration_baseline", {
            "device": "core", "cursor": 0, "revision": "",
        })
        assert baseline.structuredContent["status"] == "success"
        assert baseline.structuredContent["complete"] is True
        assert "mock-enable-secret" not in baseline.structuredContent["output"]
        comparison = await session.call_tool("compare_configuration_baseline", {
            "device": "core", "cursor": 0, "revision": "",
        })
        assert comparison.structuredContent["status"] == "success"
        assert comparison.structuredContent["changed"] is False
        assert comparison.structuredContent["complete"] is True
        fleet = await session.call_tool("compare_all_configuration_baselines", {"workers": 1})
        assert fleet.structuredContent["counts"]["unchanged"] == 1
        assert fleet.structuredContent["exit_code"] == 0
        assert "diff" not in fleet.structuredContent["results"][0]
        baseline_status = await session.call_tool(
            "get_configuration_baseline_status", {"max_age_days": 30}
        )
        assert baseline_status.structuredContent["devices"][0]["last_status"] == "unchanged"
        assert baseline_status.structuredContent["exit_code"] == 0
        topology = await session.call_tool("discover_topology", {
            "target": "core", "workers": 1, "max_age_minutes": 60,
        })
        assert topology.structuredContent["collection_counts"]["success"] == 1
        assert topology.structuredContent["counts"]["unresolved"] == 1
        cached_topology = await session.call_tool("get_topology", {
            "target": "core", "max_age_minutes": 60,
        })
        assert cached_topology.structuredContent["mock"] is True
        assert cached_topology.structuredContent["unresolved_neighbors"][0]["neighbor"] == "DIST-SW1"
        diagram = await session.call_tool("get_topology_diagram", {
            "target": "core", "location": "", "max_age_minutes": 60,
            "format": "mermaid",
        })
        assert diagram.structuredContent["diagram"].startswith("flowchart LR")
        path_result = await session.call_tool("trace_mac_path", {
            "mac_address": "0011.2233.4455", "source_device": "core",
            "max_age_minutes": 15, "refresh": True, "workers": 1,
        })
        assert path_result.structuredContent["found"] is True
        assert path_result.structuredContent["endpoint"]["interface"] == "Gi1/0/18"
        assert path_result.structuredContent["refreshed"] is True

        api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
            output=[], output_text="OSPF is running on core with one neighbor.", model="gpt-test",
        ))))
        chat = Chat(api, session, "configured-model", tools, mock=True)
        assert await chat.ask("Is OSPF running on core?") == (
            "OSPF is running on core with one neighbor."
        )
        assert api.responses.create.await_count == 1
        assert chat.last_execution.mcp_tools == ["get_ospf_status"]


async def test_vpn_status_mcp_tool_uses_fortios_adapter(tmp_path):
    path = tmp_path / "fortios.csv"
    path.write_text(
        "name,host,device_type,vendor,platform\n"
        "FW01,192.0.2.10,firewall,Fortinet,FortiOS\n"
    )
    inventory = Inventory(tmp_path / "fortios.db")
    inventory.import_csv(path)

    async with local_session(inventory.path, mock=True) as session:
        result = await session.call_tool("get_vpn_status", {"device": "FW01"})

    assert not result.isError
    assert result.structuredContent["complete"] is True
    assert result.structuredContent["has_active_vpn"] is True
    assert result.structuredContent["ipsec"]["active_count"] == 1
    assert result.structuredContent["ssl_vpn"]["active_session_count"] == 1
