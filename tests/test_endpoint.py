from datetime import datetime, timezone

import pytest

from nerd_mcp.endpoint import EndpointService
from nerd_mcp.inventory import Inventory, InventoryError
from nerd_mcp.mac import MacIndex


MAC = "00:11:22:33:44:55"


def make_inventory(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,device_hostname,device_type,vendor,platform,location\n"
        "CORE,192.0.2.1,core.example,router,Cisco,IOS-XE,Example City\n"
        "SW1,192.0.2.2,sw1.example,switch,Cisco,IOS-XE,Example City\n"
        "SW2,192.0.2.3,sw2.example,switch,Cisco,NX-OS,Example City\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return inventory


def populate(inventory):
    now = datetime.now(timezone.utc).isoformat()
    index = MacIndex(inventory)
    index.replace(
        "CORE", now, "success", None,
        [{"mac": MAC, "vlan": "20", "interface": "Gi0/0",
          "entry_type": "dynamic", "role": "uplink"}], [],
        [{"interface": "Gi0/0", "neighbor": "SW1", "neighbor_address": "192.0.2.2",
          "remote_interface": "Gi1/0/1", "protocol": "cdp"}], [], mock=True,
    )
    index.replace(
        "SW1", now, "success", None,
        [{"mac": MAC, "vlan": "20", "interface": "Gi1/0/2",
          "entry_type": "dynamic", "role": "uplink"}], [],
        [
            {"interface": "Gi1/0/1", "neighbor": "CORE", "neighbor_address": "192.0.2.1",
             "remote_interface": "Gi0/0", "protocol": "cdp"},
            {"interface": "Gi1/0/2", "neighbor": "SW2", "neighbor_address": "192.0.2.3",
             "remote_interface": "Et1/1", "protocol": "lldp"},
        ], [], mock=True,
    )
    index.replace(
        "SW2", now, "success", None,
        [{"mac": MAC, "vlan": "20", "interface": "Et1/10",
          "entry_type": "dynamic", "role": "access"}],
        [{"mac": MAC, "ip": "10.20.0.45", "interface": "Vlan20", "vrf": "default"}],
        [{"interface": "Et1/1", "neighbor": "SW1", "neighbor_address": "192.0.2.2",
          "remote_interface": "Gi1/0/2", "protocol": "lldp"}], [], mock=True,
    )


def test_ipv4_endpoint_resolves_arp_mac_attachment_and_path(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory)
    result = EndpointService(inventory).locate("10.20.0.45", "CORE", 60)
    assert result["status"] == "success" and result["complete"]
    assert result["identifier_type"] == "ipv4"
    assert result["mac_addresses"] == [MAC]
    assert result["attachment_found"] is True
    assert result["endpoints"][0]["endpoint"]["device_name"] == "SW2"
    assert result["endpoints"][0]["endpoint"]["interface"] == "Et1/10"
    assert result["endpoints"][0]["path_devices"] == ["CORE", "SW1", "SW2"]


def test_mac_endpoint_uses_same_resolution_pipeline(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory)
    result = EndpointService(inventory).locate("0011.2233.4455", "", 60)
    assert result["identifier_type"] == "mac"
    assert result["normalized_identifier"] == MAC
    assert result["ip_address"] == "10.20.0.45"
    assert result["endpoints"][0]["endpoint"]["interface"] == "Et1/10"


@pytest.mark.parametrize("identifier", ["SW2", "sw2.example", "192.0.2.3"])
def test_inventory_device_identifiers_resolve_without_collection(tmp_path, identifier):
    result = EndpointService(make_inventory(tmp_path)).locate(identifier, refresh=True)
    assert result["resolution"] == "inventory"
    assert result["inventory_devices"][0]["name"] == "SW2"
    assert result["refreshed"] is False


def test_unknown_hostname_discloses_missing_dhcp_dns_source(tmp_path):
    result = EndpointService(make_inventory(tmp_path)).locate("printer-01")
    assert result["status"] == "partial" and not result["found"]
    assert "DHCP or DNS" in result["warnings"][0]


def test_refresh_collects_once_and_resolves_mock_endpoint(tmp_path):
    source = tmp_path / "one.csv"
    source.write_text(
        "name,host,device_type,vendor,platform\n"
        "EDGE,192.0.2.10,switch,Cisco,IOS-XE\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "one.db")
    inventory.import_file(source)
    result = EndpointService(inventory, mock=True).locate(
        "10.20.0.45", max_age_minutes=15, refresh=True, workers=1
    )
    assert result["found"] and result["attachment_found"] and result["refreshed"]
    assert result["collection_counts"]["success"] == 1
    assert result["endpoints"][0]["endpoint"]["interface"] == "Gi1/0/18"


def test_stale_ip_observations_are_returned_with_incomplete_coverage(tmp_path):
    inventory = make_inventory(tmp_path)
    populate(inventory)
    with inventory.connect() as db:
        db.execute("UPDATE mac_scans SET observations_at = '2000-01-01T00:00:00+00:00'")
    result = EndpointService(inventory).locate("10.20.0.45", "CORE", 15)
    assert result["found"] and not result["complete"]
    assert {row["device"] for row in result["incomplete_devices"]} == {"CORE", "SW1", "SW2"}


@pytest.mark.parametrize("identifier", ["10.0.0.999", "2001:db8::1", "host;reload"])
def test_endpoint_rejects_unsupported_or_injected_identifiers(tmp_path, identifier):
    with pytest.raises(InventoryError):
        EndpointService(make_inventory(tmp_path)).locate(identifier)


def test_endpoint_rejects_bad_options(tmp_path):
    service = EndpointService(make_inventory(tmp_path))
    with pytest.raises(InventoryError, match="workers"):
        service.locate("10.20.0.45", workers=0)
    with pytest.raises(InventoryError, match="refresh"):
        service.locate("10.20.0.45", refresh=1)
