from datetime import datetime, timezone

import pytest

from nerd_mcp.inventory import Inventory, InventoryError
from nerd_mcp.mac import MacIndex
from nerd_mcp.pathing import MacPathService


MAC = "00:11:22:33:44:55"


def make_inventory(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,device_type,vendor,platform,location\n"
        "CORE,192.0.2.1,router,Cisco,IOS-XE,Example City\n"
        "SW1,192.0.2.2,switch,Cisco,IOS-XE,Example City\n"
        "SW2,192.0.2.3,switch,Cisco,NX-OS,Example City\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return inventory


def mac(interface, role, vlan="20"):
    return {
        "mac": MAC, "vlan": vlan, "interface": interface,
        "entry_type": "dynamic", "role": role,
    }


def neighbor(interface, name, address, remote, protocol="cdp"):
    return {
        "interface": interface, "neighbor": name,
        "neighbor_address": address, "remote_interface": remote,
        "protocol": protocol,
    }


def populate(inventory, *, one_sided=False, unmatched=False, duplicate_access=False):
    now = datetime.now(timezone.utc).isoformat()
    index = MacIndex(inventory)
    core_interface = "Gi0/9" if unmatched else "Gi0/0"
    index.replace(
        "CORE", now, "success", None, [mac(core_interface, "uplink")], [],
        [neighbor("Gi0/0", "SW1", "192.0.2.2", "Gi1/0/1")], [], mock=True,
    )
    sw1_neighbors = [
        neighbor("Gi1/0/2", "SW2", "192.0.2.3", "Et1/1", "lldp")
    ]
    if not one_sided:
        sw1_neighbors.insert(
            0, neighbor("Gi1/0/1", "CORE", "192.0.2.1", "Gi0/0")
        )
    index.replace(
        "SW1", now, "success", None, [mac("Gi1/0/2", "uplink")], [],
        sw1_neighbors, [], mock=True,
    )
    sw2_macs = [mac("Et1/10", "access")]
    if duplicate_access:
        sw2_macs.append(mac("Et1/11", "access"))
    index.replace(
        "SW2", now, "success", None, sw2_macs,
        [{"mac": MAC, "ip": "10.20.0.45", "interface": "Vlan20", "vrf": "default"}],
        [neighbor("Et1/1", "SW1", "192.0.2.2", "Gi1/0/2", "lldp")],
        [], mock=True,
    )


def test_mac_path_traces_uplinks_to_unique_access_port(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory)
    result = MacPathService(inventory).trace(MAC, "CORE", 60)
    assert result["status"] == "success" and result["complete"]
    assert result["path_devices"] == ["CORE", "SW1", "SW2"]
    assert [hop["from_interface"] for hop in result["hops"]] == ["Gi0/0", "Gi1/0/2"]
    assert result["endpoint"]["interface"] == "Et1/10"
    assert result["endpoint"]["ip_addresses"] == ["10.20.0.45"]
    assert result["confidence"] == "high"
    assert result["mock"] is True


def test_mac_path_infers_longest_observed_root(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory)
    result = MacPathService(inventory).trace("0011.2233.4455", max_age_minutes=60)
    assert result["source_device"] == "CORE"
    assert result["path_devices"] == ["CORE", "SW1", "SW2"]
    assert result["confidence"] == "medium"


def test_mac_path_reports_one_sided_and_unmatched_uplinks(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory, one_sided=True, unmatched=True)
    result = MacPathService(inventory).trace(MAC, "CORE", 60)
    assert result["status"] == "partial" and not result["path_found"]
    assert result["unresolved_hops"][0]["interface"] == "Gi0/9"
    assert any("no observed mac path" in warning.casefold() for warning in result["warnings"])


def test_mac_path_reports_ambiguous_access_endpoints(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory, duplicate_access=True)
    result = MacPathService(inventory).trace(MAC, "CORE", 60)
    assert result["status"] == "partial" and not result["complete"]
    assert any("ambiguous" in warning for warning in result["warnings"])


def test_mac_path_rejects_unknown_source_and_bad_options(tmp_path):
    service = MacPathService(make_inventory(tmp_path))
    with pytest.raises(InventoryError, match="Unknown device"):
        service.trace(MAC, "CORE;reload", 60)
    with pytest.raises(InventoryError, match="workers"):
        service.trace(MAC, workers=0)
    with pytest.raises(InventoryError, match="refresh"):
        service.trace(MAC, refresh=1)


def test_mac_path_mock_refresh_reports_collection(tmp_path):
    source = tmp_path / "one.csv"
    source.write_text(
        "name,host,device_type,vendor,platform\n"
        "CORE,192.0.2.1,switch,Cisco,IOS-XE\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "one.db")
    inventory.import_file(source)
    result = MacPathService(inventory, mock=True).trace(MAC, refresh=True, workers=1)
    assert result["collection_counts"]["success"] == 1
    assert result["found"] is True and result["mock"] is True
