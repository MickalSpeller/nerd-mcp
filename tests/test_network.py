from unittest.mock import Mock
from contextlib import contextmanager

import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from paramiko import SSHException

from nerd_mcp.domain.models import BgpStatus, ConfigurationSnapshot, OspfStatus, VpnStatus
from nerd_mcp.inventory import Inventory
from nerd_mcp.network import (
    COMMANDS, DISCOVERY_COMMANDS, HEALTH_COMMANDS, MAX_OUTPUT, MOCK_HEALTH,
    MOCK_OSPF_STATUS, OSPF_STATUS_COMMANDS, FORTIOS_COMMANDS,
    FORTIOS_DISCOVERY_COMMANDS, FORTIOS_HEALTH_COMMANDS, FORTIOS_OSPF_STATUS_COMMANDS,
    Network, parse_device_facts, parse_fortios_device_facts,
    parse_fortios_health_outputs, parse_health_outputs, parse_ospf_status,
    sanitize_configuration,
)
from nerd_mcp.vendors.fortinet.fortios import vpn as fortios_vpn
from nerd_mcp.vendors.cisco.ios import bgp as ios_bgp
from nerd_mcp.vendors.fortinet.fortios import bgp as fortios_bgp


@pytest.fixture
def setup_network(tmp_path, monkeypatch):
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    path = tmp_path / "devices.csv"
    path.write_text("name,host\ncore,192.0.2.1\n")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "test-secret")
    connection = Mock()
    connection.send_command.return_value = "healthy"
    connector = Mock(return_value=connection)
    return Network(inventory, connector=connector), connection, connector


@pytest.fixture
def fortios_network(tmp_path, monkeypatch):
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    path = tmp_path / "devices.csv"
    path.write_text(
        "name,host,device_type,vendor,platform\nFW1,192.0.2.10,firewall,Fortinet,FortiOS\n"
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(path)
    known_hosts = tmp_path / "known_hosts"; known_hosts.write_text("")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "test-secret")
    connection = Mock(); connection.send_command.return_value = "healthy"
    connector = Mock(return_value=connection)
    return Network(inventory, connector=connector), connection, connector


@pytest.mark.parametrize("operation,command", COMMANDS.items())
def test_fixed_commands_and_strict_ssh(setup_network, operation, command):
    network, connection, connector = setup_network
    assert network.inspect(operation, "core")["status"] == "success"
    connection.send_command.assert_called_once_with(command, read_timeout=30)
    connection.disconnect.assert_called_once()
    assert connector.call_args.kwargs["ssh_strict"] is True
    assert connector.call_args.kwargs["host"] == "192.0.2.1"
    assert connector.call_args.kwargs["session_log"] is None


@pytest.mark.parametrize("operation,name", [
    ("get_interfaces", "core;reload"), ("reload", "core"),
    ("get_interfaces", "192.0.2.9"), ("show version\nreload", "core"),
])
def test_injection_and_unknown_targets(setup_network, operation, name):
    network, _, connector = setup_network
    assert network.inspect(operation, name)["status"] == "error"
    connector.assert_not_called()


def test_missing_credentials(setup_network, monkeypatch):
    network, _, connector = setup_network
    monkeypatch.delenv("NERD_DEFAULT_PASSWORD")
    assert "NERD_DEFAULT_PASSWORD" in network.inspect("get_routes", "core")["error"]
    connector.assert_not_called()


@pytest.mark.parametrize("error", [NetmikoAuthenticationException("test-secret"),
    NetmikoTimeoutException("test-secret"), ReadTimeout("test-secret"),
    SSHException("test-secret"), OSError("test-secret")])
def test_connection_errors_hide_secrets(setup_network, error):
    network, _, connector = setup_network
    connector.side_effect = error
    result = network.inspect("get_routes", "core")
    assert result["status"] == "error"
    assert "test-secret" not in str(result)


def test_timeout_disconnects(setup_network):
    network, connection, _ = setup_network
    connection.send_command.side_effect = ReadTimeout("raw sensitive output")
    assert network.inspect("get_routes", "core")["status"] == "error"
    connection.disconnect.assert_called_once()


def test_truncation_redaction_and_unsupported(setup_network):
    network, connection, _ = setup_network
    connection.send_command.return_value = "test-secret " + "x" * (MAX_OUTPUT + 1)
    result = network.inspect("get_routes", "core")
    assert result["truncated"] and "test-secret" not in result["output"]
    connection.send_command.return_value = "% Invalid input detected at '^' marker."
    assert network.inspect("get_vlans", "core")["status"] == "error"


def test_mock_never_connects(setup_network):
    network, _, connector = setup_network
    network.mock = True
    assert "MOCK DATA" in network.inspect("get_device_info", "core")["output"]
    connector.assert_not_called()


def test_saved_credentials_used_without_environment(setup_network, monkeypatch):
    network, _, connector = setup_network
    monkeypatch.delenv("NERD_DEFAULT_USERNAME")
    monkeypatch.delenv("NERD_DEFAULT_PASSWORD")
    monkeypatch.setattr(  # pragma: allowlist secret (synthetic redaction fixture)
        "nerd_mcp.credentials.read_saved", lambda profile: ("saved-user", "saved-password")
    )
    assert network.inspect("get_device_info", "core")["status"] == "success"
    assert connector.call_args.kwargs["username"] == "saved-user"
    assert connector.call_args.kwargs["password"] == "saved-password"  # pragma: allowlist secret


def test_configuration_uses_fixed_command_and_redacts_secrets(setup_network):
    network, connection, _ = setup_network
    connection.send_command.return_value = """hostname core
enable secret 9 enable-value
username admin privilege 15 secret 9 user-value
snmp-server community public RO
radius server ISE
 key radius-value
interface Ethernet0/0
 ip ospf message-digest-key 1 md5 ospf-value
 standby 1 authentication md5 key-string hsrp-value
neighbor 192.0.2.2 password bgp-value
service password-encryption
description test-secret is echoed here
end"""
    result = network.configuration("core", "running")
    assert result["status"] == "success"
    assert result["command"] == "show running-config"
    assert result["redactions"] == 8
    assert "enable-value" not in result["output"]
    assert "test-secret" not in result["output"]
    assert "service password-encryption" in result["output"]
    assert "interface Ethernet0/0" in result["output"]
    connection.send_command.assert_called_once_with("show running-config", read_timeout=60)
    connection.disconnect.assert_called_once()


def test_pooled_read_timeout_reconnects_once_for_fixed_read_only_command(setup_network):
    original, _connection, _connector = setup_network
    stale = Mock()
    stale.send_command.side_effect = ReadTimeout("stale pooled session")
    fresh = Mock()
    fresh.send_command.return_value = "interface output"

    class RetryPool:
        def __init__(self):
            self.calls = 0

        @contextmanager
        def connection(self, device, device_type, read_timeout):
            self.calls += 1
            yield (stale if self.calls == 1 else fresh), "test-secret"

    pool = RetryPool()
    network = Network(original.inventory, connection_pool=pool)
    result = network.inspect("get_interfaces", "core")
    assert result["status"] == "success"
    assert result["output"] == "interface output"
    assert pool.calls == 2


def test_pooled_read_timeout_is_retried_only_once(setup_network):
    original, _connection, _connector = setup_network
    failed = Mock()
    failed.send_command.side_effect = ReadTimeout("still unavailable")

    class FailedPool:
        def __init__(self):
            self.calls = 0

        @contextmanager
        def connection(self, device, device_type, read_timeout):
            self.calls += 1
            yield failed, "test-secret"

    pool = FailedPool()
    result = Network(original.inventory, connection_pool=pool).inspect("get_interfaces", "core")
    assert result["status"] == "error"
    assert result["error"] == "SSH connection or command timed out."
    assert pool.calls == 2


def test_configuration_sources_and_rejects_injection(setup_network):
    network, connection, connector = setup_network
    assert network.configuration("core", "startup")["command"] == "show startup-config"
    connector.reset_mock()
    result = network.configuration("core", "running;reload")
    assert result["status"] == "error"
    assert "Unsupported configuration source" in result["error"]
    connector.assert_not_called()


@pytest.mark.parametrize("operation,command", FORTIOS_COMMANDS.items())
def test_fortios_inspection_uses_adapter_commands_and_driver(fortios_network, operation, command):
    network, connection, connector = fortios_network
    result = network.inspect(operation, "FW1")
    assert result["status"] == "success"
    connection.send_command.assert_called_once_with(command, read_timeout=30)
    assert connector.call_args.kwargs["device_type"] == "fortinet"
    connection.disconnect.assert_called_once()


def test_fortios_mock_facts_health_ospf_and_configuration(fortios_network):
    network, _connection, connector = fortios_network
    network.mock = True
    facts = network.discover_inventory("FW1")
    assert facts["facts"] == {
        "device_hostname": "mock-fortigate", "serial_number": "FG100FTK00000001",
        "model": "FortiGate-100F", "location": "Example Lab",
    }
    health = network.health("FW1")
    assert health["status"] == "success" and health["overall"] == "healthy"
    assert health["metrics"]["default_route"] is True
    ospf = network.ospf_status("FW1")
    assert ospf["status"] == "success" and ospf["neighbor_count"] == 1
    vpn = network.vpn_status("FW1")
    assert vpn["status"] == "success" and vpn["complete"] is True
    assert vpn["has_active_vpn"] is True
    assert vpn["ipsec"]["tunnel_count"] == 2
    assert vpn["ipsec"]["active_count"] == 1
    assert vpn["ssl_vpn"]["active_session_count"] == 1
    config = network.configuration("FW1", "running")
    assert config["status"] == "success"
    assert "mock-secret" not in config["output"] and config["redactions"] == 1
    startup = network.configuration("FW1", "startup")
    assert startup["status"] == "error" and "does not provide" in startup["error"]
    connector.assert_not_called()


def test_fortios_vpn_parsers_handle_summary_fallback_and_partial_results():
    status = fortios_vpn.parse_status(dict(fortios_vpn.MOCK_OUTPUTS))
    assert isinstance(status, VpnStatus)
    assert status.complete and status.has_active_vpn is True
    assert status.ipsec_tunnels[0].name == "Branch-HQ"
    assert status.ipsec_tunnels[0].remote_gateway == "198.51.100.10"
    assert status.ipsec_tunnels[1].status == "down"
    assert status.ssl_vpn_session_count == 1

    fallback = fortios_vpn.parse_status({
        "ipsec_summary": "Command fail. Return code -61",
        "ipsec_details": fortios_vpn.MOCK_OUTPUTS["ipsec_details"],
        "ssl_sessions": "SSL VPN Login Users:\n\nSSL VPN sessions:\n",
    })
    assert fallback.complete and fallback.has_active_vpn is True
    assert fallback.ipsec_tunnels[0].remote_gateway == "198.51.100.10"

    partial = fortios_vpn.parse_status({
        "ipsec_summary": "Command fail. Return code -61",
        "ipsec_details": "Command fail. Return code -61",
        "ssl_sessions": "SSL VPN Login Users:\n\nSSL VPN sessions:\n",
    })
    assert not partial.complete and partial.has_active_vpn is None
    assert partial.ssl_vpn_session_count == 0


def test_vpn_status_is_unsupported_without_fortios_capability(setup_network):
    network, connection, connector = setup_network
    result = network.vpn_status("core")
    assert result["status"] == "unsupported"
    assert result["has_active_vpn"] is None
    assert "supports" in result["error"]
    connector.assert_not_called()
    connection.send_command.assert_not_called()


def test_fortios_parsers_extract_facts_and_health():
    facts = parse_fortios_device_facts({
        "global": 'set hostname "FW-EXAMPLE-01"\nset location "Sample City"',
        "status": "Version: FortiGate-60F v7.4.4\nSerial-Number: FGT60FTK12345678",
    })
    assert facts["device_hostname"] == "FW-EXAMPLE-01"
    assert facts["model"] == "FortiGate-60F"
    assert facts["serial_number"] == "FGT60FTK12345678"
    assert facts["location"] == "Sample City"


def test_fortios_secret_commands_and_command_failures_are_recognized(fortios_network):
    sanitized, count = sanitize_configuration(
        'set hostname "FW1"\nset password ENC abc\nset psksecret ENC def'
    )
    assert "abc" not in sanitized and "def" not in sanitized and count == 2
    network, connection, _connector = fortios_network
    connection.send_command.return_value = "Command fail. Return code -61"
    assert network.inspect("get_neighbors", "FW1")["status"] == "error"


def test_configuration_pagination_and_revision_change(setup_network, monkeypatch):
    network, connection, _ = setup_network
    monkeypatch.setattr("nerd_mcp.network.CONFIG_PAGE_CHARS", 10)
    connection.send_command.return_value = "hostname core\ninterface Ethernet0/0\nend"
    first = network.get_configuration("core", "running", 0, "")
    assert first["status"] == "success" and not first["complete"]
    pieces = [first["output"]]
    current = first
    while not current["complete"]:
        current = network.get_configuration(
            "core", "running", current["next_cursor"], first["revision"]
        )
        pieces.append(current["output"])
    assert "".join(pieces) == "hostname core\ninterface Ethernet0/0\nend"

    connection.send_command.return_value = "hostname changed\nend"
    changed = network.get_configuration("core", "running", 10, first["revision"])
    assert changed["status"] == "error"
    assert "changed between pages" in changed["error"]
    assert changed["output"] == ""


@pytest.mark.parametrize("cursor", [-1, True, 9999])
def test_invalid_configuration_cursor(setup_network, cursor):
    network, _, _ = setup_network
    result = network.get_configuration("core", "running", cursor, "")
    assert result["status"] == "error"
    assert result["output"] == ""


def test_private_key_material_is_redacted():
    sanitized, count = sanitize_configuration(
        "-----BEGIN RSA PRIVATE KEY-----\n"  # pragma: allowlist secret (synthetic fixture)
        "secret-data\nmore-data\n-----END RSA PRIVATE KEY-----"
    )
    assert "secret-data" not in sanitized and "more-data" not in sanitized
    assert sanitized.count("[REDACTED private key material]") == 1
    assert count == 2


def test_parse_device_facts_prefers_chassis_inventory():
    facts = parse_device_facts({
        "hostname": "hostname EDGE-R1",
        "location": "snmp-server location Sample Data Center",
        "inventory": '''NAME: "Power Supply", DESCR: "AC Power Supply"
PID: PWR-1, VID: V01, SN: PSU123
NAME: "Chassis", DESCR: "Cisco Catalyst Chassis"
PID: C9300-24T, VID: V02, SN: FOC1234ABCD''',
        "version": "EDGE-R1 uptime is 1 week",
    })
    assert facts == {
        "device_hostname": "EDGE-R1", "serial_number": "FOC1234ABCD",
        "model": "C9300-24T", "location": "Sample Data Center",
    }


def test_discover_inventory_uses_fixed_commands_one_connection(setup_network):
    network, connection, _ = setup_network
    connection.send_command.side_effect = [
        "hostname CORE-R1",
        'NAME: "Chassis", DESCR: "Router"\nPID: C8000V, VID: V01, SN: ABC123',
        "snmp-server location Example City",
        "CORE-R1 uptime is 1 day",
    ]
    result = network.discover_inventory("core")
    assert result["status"] == "success"
    assert result["facts"]["device_hostname"] == "CORE-R1"
    assert result["facts"]["model"] == "C8000V"
    assert [call.args[0] for call in connection.send_command.call_args_list] == list(DISCOVERY_COMMANDS.values())
    connection.disconnect.assert_called_once()


def test_mock_inventory_discovery_never_connects(setup_network):
    network, _, connector = setup_network
    network.mock = True
    result = network.discover_inventory("core")
    assert result["status"] == "success"
    assert result["facts"]["model"] == "C9300-24T"
    connector.assert_not_called()


def test_health_uses_fixed_commands_in_one_connection(setup_network):
    network, connection, _ = setup_network
    connection.send_command.side_effect = list(MOCK_HEALTH.values())
    result = network.health("core")
    assert result["status"] == "success"
    assert result["overall"] == "healthy"
    assert result["complete"] is True
    assert result["metrics"]["interfaces_up"] == 1
    assert result["metrics"]["cpu_five_minute_percent"] == 3
    assert [call.args[0] for call in connection.send_command.call_args_list] == list(HEALTH_COMMANDS.values())
    assert all(call.kwargs["read_timeout"] == 60 for call in connection.send_command.call_args_list)
    connection.disconnect.assert_called_once()


def test_health_parser_reports_critical_and_warning_findings():
    outputs = dict(MOCK_HEALTH)
    outputs["interfaces"] = (
        "Interface IP-Address OK? Method Status Protocol\n"
        "Ethernet0/0 192.0.2.1 YES manual up down\n"
        "Ethernet0/1 unassigned YES unset down down"
    )
    outputs["interface_counters"] = (
        "Ethernet0/0 is up, line protocol is down\n"
        "  4 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored\n"
        "  3 output errors, 0 collisions, 0 interface resets"
    )
    outputs["routes"] = "Gateway of last resort is not set"
    outputs["cpu"] = "CPU utilization for five seconds: 96%/1%; one minute: 94%; five minutes: 92%"
    outputs["memory"] = "Processor Pool Total: 100000 Used: 95000 Free: 5000"
    report = parse_health_outputs(outputs, "router")
    assert report["overall"] == "critical"
    assert report["counts"]["critical"] == 3
    assert report["counts"]["warning"] == 4
    assert report["metrics"]["default_route"] is False
    assert report["metrics"]["memory_free_percent"] == 5.0


def test_health_parser_marks_unsupported_checks_incomplete():
    output = "% Invalid input detected at '^' marker."
    report = parse_health_outputs({key: output for key in HEALTH_COMMANDS})
    assert report["overall"] == "unknown"
    assert report["complete"] is False
    assert report["counts"] == {"critical": 0, "warning": 0, "ok": 0, "info": 8}


def test_health_parser_reports_unhealthy_routing_neighbors():
    outputs = dict(MOCK_HEALTH)
    outputs["ospf_neighbors"] = (
        "Neighbor ID Pri State Dead Time Address Interface\n"
        "192.0.2.2 1 EXSTART/DR 00:00:31 192.0.2.2 Ethernet0/0"
    )
    outputs["bgp_summary"] = (
        "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n"
        "198.51.100.2 4 65002 0 0 1 0 0 never Active"
    )
    report = parse_health_outputs(outputs)
    assert report["overall"] == "critical"
    assert report["metrics"]["ospf_not_full"] == 1
    assert report["metrics"]["bgp_not_established"] == 1
    assert report["counts"]["critical"] == 2


def test_health_failure_hides_connection_details(setup_network):
    network, _, connector = setup_network
    connector.side_effect = NetmikoTimeoutException("test-secret internal details")
    result = network.health("core")
    assert result["status"] == "error"
    assert result["overall"] == "unknown"
    assert "test-secret" not in str(result)


def test_ospf_status_uses_two_fixed_commands_in_one_connection(setup_network):
    network, connection, _ = setup_network
    connection.send_command.side_effect = list(MOCK_OSPF_STATUS.values())
    result = network.ospf_status("core")
    assert result["status"] == "success"
    assert result["running"] is True
    assert result["processes"] == [{"process_id": "1", "router_id": "192.0.2.1"}]
    assert result["neighbor_count"] == 1
    assert result["neighbors"][0]["state"] == "FULL/DR"
    assert result["complete"] is True
    assert [call.args[0] for call in connection.send_command.call_args_list] == list(
        OSPF_STATUS_COMMANDS.values()
    )
    assert all(call.kwargs["read_timeout"] == 30 for call in connection.send_command.call_args_list)
    connection.disconnect.assert_called_once()


def test_ospf_status_parser_reports_inactive_and_unknown_separately():
    inactive = parse_ospf_status({
        "process": "% OSPF not enabled", "neighbors": "% OSPF not enabled",
    })
    assert inactive["running"] is False
    assert inactive["process_count"] == 0

    unknown = parse_ospf_status({
        "process": "% Invalid input detected at '^' marker.",
        "neighbors": "% Authorization failed",
    })
    assert unknown["running"] is None
    assert unknown["complete"] is False
    assert len(unknown["warnings"]) == 2


def test_bgp_summary_parser_reports_established_down_and_router_identity():
    status = ios_bgp.parse_status(dict(ios_bgp.MOCK_OUTPUTS))
    assert isinstance(status, BgpStatus)
    assert status.router_id == "1.1.1.1" and status.local_as == 65001
    assert status.running is True and status.complete is True
    assert status.neighbors[0].neighbor == "2.2.2.2"
    assert status.neighbors[0].established is True
    assert status.neighbors[0].up_down == "1d02h"
    assert status.neighbors[0].prefixes_received == 8
    assert status.neighbors[1].established is False
    assert status.neighbors[1].state == "Active"
    assert status.neighbors[1].up_down == "00:04:31"


def test_bgp_status_uses_vendor_adapter_and_normalized_contract(setup_network, fortios_network):
    cisco, _connection, connector = setup_network
    cisco.mock = True
    result = cisco.bgp_status("core")
    assert result["status"] == "success"
    assert result["router_id"] == "1.1.1.1"
    assert result["established_count"] == 1 and result["neighbor_count"] == 2
    assert result["neighbors"][0]["up_down"] == "1d02h"
    connector.assert_not_called()

    firewall, _connection, connector = fortios_network
    firewall.mock = True
    result = firewall.bgp_status("FW1")
    assert result["status"] == "success"
    assert result["commands"] == ["get router info bgp summary"]
    assert result["neighbors"][0]["established"] is True
    assert result["neighbors"][0]["up_down"] == "02:14:09"
    connector.assert_not_called()


def test_bgp_configuration_uses_filtered_fixed_command_and_redacts(setup_network):
    network, connection, _ = setup_network
    connection.send_command.return_value = (
        "router bgp 65001\n neighbor 2.2.2.2 remote-as 65002\n"
        " neighbor 2.2.2.2 password test-secret"
    )
    result = network.bgp_configuration("core")
    assert result["status"] == "success"
    assert "remote-as 65002" in result["output"]
    assert "test-secret" not in result["output"]
    assert "REDACTED" in result["output"]
    connection.send_command.assert_called_once_with(
        "show running-config | section ^router bgp", read_timeout=30
    )


def test_bgp_routes_uses_fixed_live_command(setup_network):
    network, connection, _ = setup_network
    connection.send_command.return_value = (
        "     Network          Next Hop            Metric LocPrf Weight Path\n"
        " *>  10.20.0.0/24     2.2.2.2                  0    100      0 i"
    )
    result = network.bgp_routes("core")
    assert result["status"] == "success"
    assert "10.20.0.0/24" in result["output"]
    assert result["command"] == "show ip bgp"
    connection.send_command.assert_called_once_with("show ip bgp", read_timeout=30)


def test_bgp_summary_parser_reports_unavailable_data_as_incomplete():
    status = fortios_bgp.parse_status({"summary": "Command fail. Return code -61"})
    assert status.running is None and status.complete is False
    assert status.neighbors == () and status.warnings


def test_ospf_and_configuration_collectors_expose_typed_contracts(setup_network):
    network, connection, _ = setup_network
    connection.send_command.side_effect = list(MOCK_OSPF_STATUS.values())
    ospf = network.collect_ospf_status("core")
    assert ospf.status == "success"
    assert isinstance(ospf.data, OspfStatus)
    assert ospf.data.processes[0].router_id == "192.0.2.1"

    connection.reset_mock()
    connection.send_command.side_effect = None
    connection.send_command.return_value = "hostname core\nend"
    configuration = network.collect_configuration("core")
    assert configuration.status == "success"
    assert isinstance(configuration.data, ConfigurationSnapshot)
    assert configuration.data.output == "hostname core\nend"
