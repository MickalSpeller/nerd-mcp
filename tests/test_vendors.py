"""Vendor capabilities and normalized observations use synthetic output only."""
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from nerd_mcp.domain.models import CollectionResult, Interface
from nerd_mcp.inventory import Device
from nerd_mcp.mac import adapter_for
from nerd_mcp.network import Network, MAX_OUTPUT, parse_device_facts, parse_fortios_device_facts
from nerd_mcp.routing import RouteTracer
from nerd_mcp.vendors.cisco.ios import collector as ios
from nerd_mcp.vendors.fortinet.fortios import collector as fortios
from nerd_mcp.vendors.registry import platform_for, supports


@pytest.mark.parametrize("vendor, platform, expected", [
    ("Cisco", "", "cisco_ios"), ("Cisco", "IOS/IOS-XE", "cisco_ios"),
    ("Cisco", "ios_xe", "cisco_ios"), ("Cisco", "NX-OS", "cisco_nxos"),
    ("Fortinet", "", "fortinet"), ("FortiGate", "FortiOS", "fortinet"),
    ("Aruba", "", "aruba_osswitch"), ("Aruba", "AOS-CX", "aruba_aoscx"),
    ("HPE", "AOS-Switch", "aruba_osswitch"),
    ("Cisco", "unknown-ios", None), ("Aruba", "unknown-cx", None),
    ("Fortinet", "future-fortios", None), ("Juniper", "Junos", None),
])
def test_explicit_platform_selection(vendor, platform, expected):
    device = Device("test", "192.0.2.1", vendor=vendor, platform=platform)
    selected = platform_for(device)
    assert (selected.name if selected else None) == expected
    assert (adapter_for(device) is not None) == (expected is not None)
    assert supports(device, "facts") == (expected in {"cisco_ios", "fortinet"})
    assert supports(device, "ospf_trace") == (expected == "cisco_ios")
    assert not supports(device, "arbitrary_command")


@pytest.mark.parametrize("vendor,platform,module", [("Cisco", "IOS-XE", ios), ("Fortinet", "FortiOS", fortios)])
def test_mock_normalized_facts_and_interfaces_preserve_legacy(vendor, platform, module):
    inventory = Mock()
    inventory.get.return_value = Device("test", "192.0.2.1", vendor=vendor, platform=platform)
    network = Network(inventory, mock=True, connector=Mock(side_effect=AssertionError("SSH")))
    facts = network.collect_facts("test")
    assert facts.status == "success" and facts.complete
    assert facts.schema_version == 1 and facts.source == "mock" and facts.timestamp
    assert asdict(facts.data) == module.parse_facts(module.MOCK_DISCOVERY)
    assert network.discover_inventory("test")["facts"] == asdict(facts.data)
    interfaces = network.collect_interfaces("test")
    assert interfaces.status == "success" and interfaces.complete
    assert interfaces.data[0].address == "192.0.2.1"
    assert interfaces.data[0].status == "up"
    assert network.inspect("get_interfaces", "test")["output"] == interfaces.raw_output
    assert "raw_output" not in repr(interfaces)
    inventory.update_facts.assert_not_called()


def test_existing_fact_parser_imports_are_forwarding_aliases():
    assert parse_device_facts is ios.parse_facts
    assert parse_fortios_device_facts is fortios.parse_facts


def test_ios_unknown_unassigned_and_recognized_empty_are_distinct():
    header = "Interface IP-Address OK? Method Status Protocol\n"
    rows, warnings = ios.parse_interfaces(header +
        "Gi1 unassigned YES unset administratively down down\n"
        "Gi2 malformed YES manual up up\n")
    assert rows[0] == Interface("Gi1", None, "administratively down", "down", True)
    assert rows[1].address is None and rows[1].unassigned is None
    assert warnings
    assert ios.parse_interfaces(header) == ((), ())
    assert ios.parse_interfaces("")[1]
    assert ios.parse_interfaces("unexpected output")[1]


def test_fortios_missing_fields_and_unassigned_address():
    rows, warnings = fortios.parse_interfaces(
        "== [ port1 ]\nname: port1 ip: 0.0.0.0 0.0.0.0 status: down\n"
        "== [ port2 ]\nname: port2 mode: static\n"
    )
    assert rows[0] == Interface("port1", None, "down", None, True)
    assert rows[1] == Interface("port2", None, None, None, None)
    assert warnings
    assert fortios.parse_interfaces("unrecognized")[1]


def network_with_outputs(output, vendor="Cisco", platform="IOS-XE"):
    inventory = Mock()
    inventory.get.return_value = Device("test", "192.0.2.1", vendor=vendor, platform=platform)
    network = Network(inventory)
    network._read_many = Mock(return_value=({"result": output}, "synthetic-secret"))
    return network


def test_partial_facts_keep_unknowns_and_legacy_shape():
    network = network_with_outputs("")
    network._read_many.return_value = ({"hostname": "hostname test", "inventory": "% Invalid input"}, None)
    result = network.collect_facts("test")
    assert result.status == "partial" and not result.complete and result.warnings
    assert result.data.device_hostname == "test" and result.data.model is None
    legacy = network.discover_inventory("test")
    assert legacy["status"] == "success" and legacy["warning"] is None
    assert legacy["facts"]["model"] == ""
    network._read_many.return_value = ({}, None)
    assert "no supported device facts" in network.discover_inventory("test")["warning"]


@pytest.mark.parametrize("vendor,platform", [("Cisco", "NX-OS"), ("Aruba", "AOS-CX"), ("Cisco", "unknown-ios"), ("Juniper", "Junos")])
def test_unsupported_capability_never_collects(vendor, platform):
    network = network_with_outputs("", vendor, platform)
    for result in (network.collect_facts("test"), network.collect_interfaces("test")):
        assert result.status == "unsupported" and not result.complete
        assert result.error_code == "unsupported_capability" and result.data is None
    assert network.inspect("get_interfaces", "test")["status"] == "error"
    network._read_many.assert_not_called()


def test_interface_command_rejection_and_safe_exception():
    network = network_with_outputs("% Invalid input synthetic-secret")
    result = network.collect_interfaces("test")
    assert result.status == "error" and result.error_code == "command_rejected"
    assert result.data is None and not result.complete
    assert "synthetic-secret" not in result.raw_output
    network._read_many.side_effect = RuntimeError("synthetic-secret")
    result = network.collect_interfaces("test")
    assert result.status == "error" and "synthetic-secret" not in str(result)


def test_interface_truncation_preserves_legacy_text_but_not_incomplete_row():
    first = "Gi1 192.0.2.1 YES manual up up\n"
    output = first + "\n" * (MAX_OUTPUT - len(first) - 5) + "Gi2 192.0.2.2 YES manual up up"
    network = network_with_outputs(output)
    result = network.collect_interfaces("test")
    assert result.status == "partial" and not result.complete and result.truncated
    assert [row.name for row in result.data] == ["Gi1"]
    assert "truncated" in result.warnings[-1]
    legacy = network.inspect("get_interfaces", "test")
    assert legacy["status"] == "success" and legacy["truncated"]
    assert legacy["output"] == output[:MAX_OUTPUT] + "\n[OUTPUT TRUNCATED]"


def test_route_correlation_uses_structured_rows_and_retains_coverage_warning():
    inventory = Mock()
    inventory.list.return_value = [Device("R1", "192.0.2.1")]
    tracer = RouteTracer(inventory)
    tracer.network = Mock()
    tracer.network.inspect.side_effect = AssertionError("must not reparse raw output")
    tracer.network.collect_interfaces.return_value = CollectionResult(
        "R1", "interfaces", "2026-09-10T00:00:00+00:00", "mock", status="partial",
        data=(Interface("Gi1", "192.0.2.8", "up", "up"),), truncated=True,
        warnings=("truncated",), raw_output="unrelated text",
    )
    owners, checks = tracer._interface_owners({"192.0.2.8"}, 1)
    assert owners["192.0.2.8"][0]["interface"] == "Gi1"
    assert checks[0]["status"] == "partial" and "truncated" in checks[0]["error"]
    tracer.network.inspect.assert_not_called()
