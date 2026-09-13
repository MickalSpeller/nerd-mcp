from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from nerd_mcp.inventory import Device, Inventory, InventoryError
from nerd_mcp.mac import (
    MacService,
    adapter_for,
    normalize_mac,
    parse_arp_table,
    parse_interface_health,
    parse_mac_table,
    parse_uplinks,
    normalize_interface,
)


def make_inventory(tmp_path, rows=None):
    rows = rows or ["core,192.0.2.1,switch,Cisco,IOS/IOS-XE"]
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text(
        "name,host,device_type,vendor,platform\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(csv_path)
    return inventory


@pytest.mark.parametrize("value", [
    "0011.2233.4455", "00:11:22:33:44:55", "00-11-22-33-44-55", "001122-334455",
])
def test_normalize_mac_formats(value):
    assert normalize_mac(value) == "00:11:22:33:44:55"


@pytest.mark.parametrize("value", ["bad", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"])
def test_normalize_mac_rejects_invalid_group_addresses(value):
    with pytest.raises(InventoryError):
        normalize_mac(value)


@pytest.mark.parametrize("value", ["e1/1", "Et1/1", "Eth1/1", "Ethernet1/1"])
def test_normalize_interface_equivalent_ethernet_abbreviations(value):
    assert normalize_interface(value) == "e1/1"


def test_normalize_interface_rejects_command_injection():
    with pytest.raises(InventoryError):
        normalize_interface("e1/1; reload")


@pytest.mark.parametrize("device,family,netmiko_type", [
    (Device("ios", "192.0.2.1", vendor="Cisco", platform="IOS-XE"), "cisco_ios", "cisco_ios"),
    (Device("nx", "192.0.2.2", vendor="Cisco", platform="NX-OS"), "cisco_nxos", "cisco_nxos"),
    (Device("cx", "192.0.2.3", vendor="Aruba", platform="AOS-CX"), "aruba_aoscx", "aruba_aoscx"),
    (Device("as", "192.0.2.4", vendor="Aruba", platform="AOS-Switch"), "aruba_osswitch", "aruba_osswitch"),
    (Device("fg", "192.0.2.5", vendor="Fortinet", platform="FortiOS"), "fortinet", "fortinet"),
])
def test_adapter_selection(device, family, netmiko_type):
    adapter = adapter_for(device)
    assert adapter.family == family
    assert adapter.netmiko_type == netmiko_type
    assert adapter_for(Device("x", "192.0.2.9", vendor="Unknown", platform="Unknown")) is None


def test_vendor_mac_and_arp_parsers():
    ios = parse_mac_table("20 0011.2233.4455 DYNAMIC Gi1/0/18", "cisco_ios")
    cx = parse_mac_table("20 00:11:22:33:44:55 dynamic 1/1/18", "aruba_aoscx")
    aos = parse_mac_table("001122-334455 18 20", "aruba_osswitch")
    forti = parse_mac_table("3 8 dmz 00:11:22:33:44:55 194", "fortinet")
    assert ios[0] == {"mac": "00:11:22:33:44:55", "vlan": "20", "interface": "Gi1/0/18", "entry_type": "dynamic"}
    assert cx[0]["interface"] == "1/1/18" and cx[0]["vlan"] == "20"
    assert aos[0]["interface"] == "18" and aos[0]["vlan"] == "20"
    assert forti[0]["interface"] == "dmz"
    arp = parse_arp_table("Internet 10.20.0.45 2 0011.2233.4455 ARPA Vlan20")
    assert arp[0]["ip"] == "10.20.0.45" and arp[0]["interface"] == "Vlan20"


def test_topology_and_interface_health_parsing():
    outputs = {
        "trunks": "Gi1/0/48 on 802.1q trunking 1",
        "cdp": (
            "Device ID: DIST-SW1\nIP address: 192.0.2.2\n"
            "Interface: GigabitEthernet1/0/48, Port ID (outgoing port): Gi1/0/1"
        ),
    }
    uplinks, neighbors = parse_uplinks(outputs, "cisco_ios")
    assert {"Gi1/0/48", "GigabitEthernet1/0/48"} <= uplinks
    assert neighbors[0]["neighbor"] == "DIST-SW1"
    assert neighbors[0]["neighbor_address"] == "192.0.2.2"
    assert neighbors[0]["remote_interface"] == "Gi1/0/1"
    health = parse_interface_health(
        "GigabitEthernet1/0/18 is up, line protocol is up\n"
        "  Description: endpoint\n  Full-duplex, 1000Mb/s\n"
        "  3 input errors, 2 CRC, 0 frame\n  4 output errors, 0 collisions"
    )[0]
    assert health["description"] == "endpoint"
    assert (health["input_errors"], health["crc_errors"], health["output_errors"]) == (3, 2, 4)


@pytest.mark.parametrize("output,local,neighbor,address,remote", [
    (
        "Port : 1/1/10\nNeighbor Chassis-Name : access-01.example.com\n"
        "Neighbor Management-Address : 192.0.2.20\nNeighbor Port-ID : 1/1/48",
        "1/1/10", "access-01.example.com", "192.0.2.20", "1/1/48",
    ),
    (
        "Local Port : 24\nSysName : access-02\nPortId : 48\n"
        "Remote Management Address\n  Type : ipv4\n  Address : 192.0.2.21",
        "24", "access-02", "192.0.2.21", "48",
    ),
])
def test_aruba_lldp_detail_parsing(output, local, neighbor, address, remote):
    _, neighbors = parse_uplinks({"lldp": output}, "aruba_aoscx")
    assert neighbors == [{
        "interface": local,
        "neighbor": neighbor,
        "neighbor_address": address,
        "remote_interface": remote,
        "protocol": "lldp",
    }]


def test_mock_scan_location_cache_and_troubleshooting(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    scan = service.scan("core", workers=1)
    assert scan["status"] == "success"
    assert scan["counts"] == {"success": 1, "partial": 0, "error": 0, "unsupported": 0}
    assert "output" not in str(scan).casefold()

    location = MacService(inventory).locate("0011.2233.4455")
    assert location["found"] and location["complete"] and location["confidence"] == "high"
    assert location["likely_endpoint"]["interface"] == "Gi1/0/18"
    assert location["ip_addresses"] == ["10.20.0.45"]
    assert len(location["matches"]) == 1  # The SVI ARP row is correlation, not a second endpoint.
    assert location["mock"] and location["mock_devices"] == ["core"]
    assert service.troubleshoot("00:11:22:33:44:55")["healthy"]

    with inventory.connect() as db:
        db.execute("UPDATE mac_interface_health SET crc_errors = 7 WHERE device_name = 'core'")
    troubled = service.troubleshoot("00:11:22:33:44:55")
    assert not troubled["healthy"]
    assert "CRC 7" in troubled["issues"][0]

    with inventory.connect() as db:
        tables = ("mac_observations", "arp_observations", "mac_neighbors", "mac_interface_health")
        stored = " ".join(str(tuple(row)) for table in tables for row in db.execute(f"SELECT * FROM {table}"))
    assert "Mac Address Table" not in stored


def test_reverse_interface_lookup_returns_every_mac_and_ip_correlation(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    service.scan("core", 1)
    result = service.interface_macs("core", "GigabitEthernet1/0/18")
    assert result["complete"] and result["found"] and result["count"] == 1
    assert result["matched_interfaces"] == ["Gi1/0/18"]
    assert result["observations"][0]["mac"] == "00:11:22:33:44:55"
    assert result["observations"][0]["ip_addresses"] == ["10.20.0.45"]
    assert result["interface_health"]["status"] == "up"
    assert result["mock"] is True

    empty = service.interface_macs("core", "Gi1/0/19")
    assert empty["complete"] and not empty["found"]
    assert "No learned MAC addresses" in empty["message"]


def test_device_mac_table_returns_normalized_rows_and_ip_correlation(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    service.scan("core", 1)

    result = service.device_macs("core")

    assert result["complete"] and result["found"]
    assert result["scan_status"] == "success"
    assert result["count"] == len(result["observations"])
    assert result["mock"] is True
    endpoint = next(
        row for row in result["observations"]
        if row["mac"] == "00:11:22:33:44:55"
    )
    assert endpoint == {
        "mac": "00:11:22:33:44:55",
        "vlan": "20",
        "interface": "Gi1/0/18",
        "entry_type": "dynamic",
        "role": "access",
        "observed_at": result["observations_at"],
        "ip_addresses": ["10.20.0.45"],
    }


def test_device_mac_table_reports_missing_and_stale_observations(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    missing = service.device_macs("core")
    assert not missing["complete"] and missing["scan_status"] == "not_scanned"
    assert missing["count"] == 0

    service.scan("core", 1)
    with inventory.connect() as db:
        db.execute("UPDATE mac_scans SET observations_at = '2000-01-01T00:00:00+00:00'")
    stale = service.device_macs("core")
    assert stale["found"] and not stale["complete"]
    assert stale["scan_status"] == "stale"


def test_device_arp_table_returns_normalized_rows(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    service.scan("core", 1)

    result = service.device_arps("core")

    assert result["complete"] and result["found"]
    assert result["scan_status"] == "success"
    assert result["count"] == len(result["observations"])
    assert result["mock"] is True
    assert result["observations"][0] == {
        "ip": "10.20.0.45",
        "mac": "00:11:22:33:44:55",
        "interface": "Vlan20",
        "vrf": "default",
        "observed_at": result["observations_at"],
    }


def test_device_arp_table_reports_missing_and_stale_observations(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    missing = service.device_arps("core")
    assert not missing["complete"] and missing["scan_status"] == "not_scanned"
    assert missing["count"] == 0

    service.scan("core", 1)
    with inventory.connect() as db:
        db.execute("UPDATE mac_scans SET observations_at = '2000-01-01T00:00:00+00:00'")
    stale = service.device_arps("core")
    assert stale["found"] and not stale["complete"]
    assert stale["scan_status"] == "stale"


def test_reverse_nxos_interface_lookup_accepts_short_e_alias(tmp_path):
    inventory = make_inventory(tmp_path, ["SW2,192.0.2.2,switch,Cisco,NX-OS"])
    service = MacService(inventory, mock=True)
    service.index.replace(
        "SW2", datetime.now(timezone.utc).isoformat(), "success", None,
        [{"mac": "00:11:22:33:44:55", "vlan": "1", "interface": "Et1/1",
          "entry_type": "dynamic", "role": "access"}],
        [], [], [], mock=True,
    )
    result = service.interface_macs("SW2", "e1/1")
    assert result["complete"] and result["count"] == 1
    assert result["matched_interfaces"] == ["Et1/1"]


def test_failed_refresh_preserves_last_observations_and_reports_incomplete(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    service.scan("core", 1)
    service.index.record_failure("core", datetime.now(timezone.utc).isoformat(), "error", "SSH failed")
    result = service.locate("00:11:22:33:44:55")
    assert result["found"]
    assert not result["complete"]
    assert result["incomplete_devices"][0]["status"] == "error"


def test_stale_observations_are_retained_but_disclosed(tmp_path):
    inventory = make_inventory(tmp_path)
    service = MacService(inventory, mock=True)
    service.scan("core", 1)
    with inventory.connect() as db:
        db.execute("UPDATE mac_scans SET observations_at = '2000-01-01T00:00:00+00:00'")
        db.execute("UPDATE mac_observations SET observed_at = '2000-01-01T00:00:00+00:00'")
    result = service.locate("00:11:22:33:44:55", 15)
    assert result["found"] and not result["complete"]
    assert result["incomplete_devices"][0]["status"] == "stale"


def test_all_mock_vendor_adapters_and_unsupported_status(tmp_path):
    inventory = make_inventory(tmp_path, [
        "ios,192.0.2.1,switch,Cisco,IOS-XE",
        "nxos,192.0.2.2,switch,Cisco,NX-OS",
        "cx,192.0.2.3,switch,Aruba,AOS-CX",
        "aos,192.0.2.4,switch,Aruba,AOS-Switch",
        "fg,192.0.2.5,firewall,Fortinet,FortiOS",
        "other,192.0.2.6,switch,Other,OtherOS",
    ])
    result = MacService(inventory, mock=True).scan("all", workers=3)
    assert result["counts"] == {"success": 5, "partial": 0, "error": 0, "unsupported": 1}
    assert result["status"] == "partial"
    by_name = {row["device"]: row for row in result["results"]}
    supported = ("ios", "nxos", "cx", "aos", "fg")
    assert all(by_name[name]["mac_count"] >= 1 for name in supported)
    tables = {name: MacService(inventory).device_macs(name) for name in supported}
    assert all(table["complete"] and table["count"] >= 1 for table in tables.values())
    row_keys = {"mac", "vlan", "interface", "entry_type", "role", "observed_at", "ip_addresses"}
    assert all(set(table["observations"][0]) == row_keys for table in tables.values())
    arp_tables = {name: MacService(inventory).device_arps(name) for name in supported}
    assert all(table["complete"] and table["count"] >= 1 for table in arp_tables.values())
    arp_keys = {"ip", "mac", "interface", "vrf", "observed_at"}
    assert all(set(table["observations"][0]) == arp_keys for table in arp_tables.values())


def test_live_collection_uses_fixed_commands_strict_host_keys_and_cleanup(tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key", encoding="utf-8")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    values = {
        "show mac address-table": "20 0011.2233.4455 DYNAMIC Gi1/0/18",
        "show ip arp": "Internet 10.20.0.45 2 0011.2233.4455 ARPA Vlan20",
        "show interfaces trunk": "Gi1/0/48 on 802.1q trunking 1",
        "show etherchannel summary": "",
        "show cdp neighbors detail": "",
        "show lldp neighbors detail": "",
        "show interfaces": "GigabitEthernet1/0/18 is up, line protocol is up",
    }
    connection = Mock()
    connection.send_command.side_effect = lambda command, read_timeout: values[command]
    connector = Mock(return_value=connection)
    result = MacService(inventory, connector=connector).scan("core", 1)
    assert result["status"] == "success"
    assert connector.call_args.kwargs["ssh_strict"] is True
    assert connector.call_args.kwargs["alt_key_file"] == str(known_hosts)
    assert connector.call_args.kwargs["session_log"] is None
    assert [call.args[0] for call in connection.send_command.call_args_list] == list(values)
    connection.disconnect.assert_called_once()


def test_unknown_target_bad_limits_and_injection_never_connect(tmp_path):
    inventory = make_inventory(tmp_path)
    connector = Mock()
    service = MacService(inventory, connector=connector)
    for target in ("missing", "core;reload"):
        with pytest.raises(InventoryError):
            service.scan(target, 1)
    for workers in (0, 17, True):
        with pytest.raises(InventoryError):
            service.scan("core", workers)
    for age in (0, 10081, True):
        with pytest.raises(InventoryError):
            service.locate("00:11:22:33:44:55", age)
        with pytest.raises(InventoryError):
            service.device_arps("core", age)
    connector.assert_not_called()


def test_missing_credentials_and_oversized_output_fail_cleanly(tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key", encoding="utf-8")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.delenv("NERD_DEFAULT_USERNAME", raising=False)
    monkeypatch.delenv("NERD_DEFAULT_PASSWORD", raising=False)
    monkeypatch.delenv("CISCO_DEFAULT_USERNAME", raising=False)
    monkeypatch.delenv("CISCO_DEFAULT_PASSWORD", raising=False)
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    connector = Mock()
    missing = MacService(inventory, connector=connector).scan("core", 1)["results"][0]
    assert missing["status"] == "error" and "credentials" in missing["error"]
    connector.assert_not_called()

    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "secret")
    monkeypatch.setattr("nerd_mcp.mac.MAX_COMMAND_OUTPUT_CHARS", 5)
    connection = Mock()
    connection.send_command.return_value = "too much output"
    oversized = MacService(
        inventory, connector=Mock(return_value=connection)
    ).scan("core", 1)["results"][0]
    assert oversized["status"] == "error" and "character limit" in oversized["error"]
    connection.disconnect.assert_called_once()


def test_fortinet_bridge_name_is_validated_before_dynamic_command(tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path, ["fw,192.0.2.1,firewall,Fortinet,FortiOS"])
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key", encoding="utf-8")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    connection = Mock()
    connection.send_command.side_effect = [
        "1. dmz fdb:\n2. bad;reboot fdb:",
        "10.20.0.45 0 00:11:22:33:44:55 dmz",
        "",
        "3 8 dmz 00:11:22:33:44:55 194",
    ]
    service = MacService(inventory, connector=Mock(return_value=connection))
    result = service.scan("fw", 1)
    commands = [call.args[0] for call in connection.send_command.call_args_list]
    assert result["status"] == "success"
    assert "diagnose netlink brctl name host dmz" in commands
    assert not any("reboot" in command for command in commands)


def test_neighbor_only_scan_runs_only_discovery_commands_and_preserves_rows_on_failure(
        tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key", encoding="utf-8")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)
    connection = Mock()
    connection.send_command.side_effect = [
        "Device ID: SW1\nInterface: Gi0/1, Port ID (outgoing port): Gi0/2",
        "",
        "% Invalid input detected",
        "% Invalid input detected",
    ]
    service = MacService(inventory, connector=Mock(return_value=connection))
    first = service.scan_neighbors("core", 1)
    assert first["status"] == "success" and first["collector"] == "neighbors_only"
    assert first["results"][0]["commands"] == [
        "show cdp neighbors detail", "show lldp neighbors detail",
    ]
    second = service.scan_neighbors("core", 1)
    assert second["status"] == "partial"
    with service.index.connect() as db:
        neighbors = [dict(row) for row in db.execute(
            "SELECT * FROM mac_neighbors WHERE device_name = 'core'"
        )]
        scan = dict(db.execute(
            "SELECT * FROM topology_scans WHERE device_name = 'core'"
        ).fetchone())
    assert neighbors[0]["neighbor"] == "SW1"
    assert scan["status"] == "partial" and scan["observations_at"]
