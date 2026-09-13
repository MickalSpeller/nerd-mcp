from datetime import datetime, timezone

import pytest

from nerd_mcp.inventory import Inventory, InventoryError
from nerd_mcp.mac import MacIndex
from nerd_mcp.topology import TopologyService


def make_inventory(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,device_hostname,device_type,vendor,platform,location\n"
        "R1,192.0.2.1,R1.example.com,router,Cisco,IOS-XE,Example City\n"
        "SW1,192.0.2.2,SW1,switch,Cisco,IOS-XE,Example City\n"
        "EDGE,192.0.2.3,EDGE,switch,Aruba,AOS-CX,Dallas\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return inventory


def record(index, device, neighbors, timestamp=None, status="success", mock=True):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    index.replace(device, timestamp, status, None, [], [], neighbors, [], mock=mock)


def test_topology_correlates_and_deduplicates_bidirectional_links(tmp_path):
    inventory = make_inventory(tmp_path)
    index = MacIndex(inventory)
    record(index, "R1", [
        {
            "interface": "Gi0/0", "neighbor": "SW1.example.com",
            "neighbor_address": "192.0.2.2", "remote_interface": "Gi1/0/1",
            "protocol": "cdp",
        },
        {
            "interface": "Gi0/1", "neighbor": "WAN-ISP", "neighbor_address": "",
            "remote_interface": "", "protocol": "cdp",
        },
    ])
    record(index, "SW1", [{
        "interface": "GigabitEthernet1/0/1", "neighbor": "R1",
        "neighbor_address": "192.0.2.1", "remote_interface": "GigabitEthernet0/0",
        "protocol": "lldp",
    }])
    record(index, "EDGE", [])
    result = TopologyService(inventory).get("all", 60)
    assert result["status"] == "partial" and result["complete"] is False
    assert result["counts"] == {
        "nodes": 3, "links": 1, "bidirectional": 1, "one_sided": 0,
        "unresolved": 1, "incomplete_devices": 0,
    }
    link = result["links"][0]
    assert link["a"] == {"device": "R1", "interface": "Gi0/0"}
    assert link["b"] == {"device": "SW1", "interface": "GigabitEthernet1/0/1"}
    assert link["protocols"] == ["cdp", "lldp"]
    assert link["bidirectional"] is True and link["confidence"] == "high"
    assert result["unresolved_neighbors"][0]["neighbor"] == "WAN-ISP"
    assert result["mock"] is True


def test_topology_reports_one_sided_links_and_filters_one_device(tmp_path):
    inventory = make_inventory(tmp_path)
    index = MacIndex(inventory)
    record(index, "R1", [{
        "interface": "Gi0/0", "neighbor": "SW1", "neighbor_address": "192.0.2.2",
        "remote_interface": "Gi1/0/1", "protocol": "cdp",
    }])
    record(index, "SW1", [])
    record(index, "EDGE", [])
    result = TopologyService(inventory).get("R1", 60)
    assert result["counts"]["links"] == 1
    assert result["counts"]["one_sided"] == 1
    assert {node["device"] for node in result["nodes"]} == {"R1", "SW1"}
    assert result["links"][0]["b"]["interface"] == "Gi1/0/1"


def test_topology_discloses_stale_missing_and_failed_collection(tmp_path):
    inventory = make_inventory(tmp_path)
    index = MacIndex(inventory)
    record(index, "R1", [], timestamp="2000-01-01T00:00:00+00:00")
    index.record_failure("SW1", datetime.now(timezone.utc).isoformat(), "error", "SSH failed")
    result = TopologyService(inventory).get("all", 60)
    states = {row["device"]: row["status"] for row in result["incomplete_devices"]}
    assert states == {"EDGE": "not_scanned", "R1": "stale", "SW1": "error"}
    assert result["complete"] is False


def test_topology_discloses_platform_without_neighbor_collection(tmp_path):
    source = tmp_path / "fortinet.csv"
    source.write_text(
        "name,host,device_type,vendor,platform\n"
        "FW1,192.0.2.10,firewall,Fortinet,FortiOS\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "fortinet.db")
    inventory.import_file(source)
    record(MacIndex(inventory), "FW1", [])
    result = TopologyService(inventory).get("all", 60)
    assert result["counts"]["incomplete_devices"] == 1
    assert result["incomplete_devices"][0]["status"] == "unsupported"
    assert "CDP or LLDP" in result["incomplete_devices"][0]["error"]


def test_topology_mock_discovery_refreshes_current_observations(tmp_path):
    inventory = make_inventory(tmp_path)
    result = TopologyService(inventory, mock=True).discover("R1", workers=1)
    assert result["collection_counts"]["success"] == 1
    assert result["collection_status"] == "success"
    assert result["unresolved_neighbors"][0]["neighbor"] == "DIST-SW1"
    assert result["mock"] is True
    with MacIndex(inventory).connect() as db:
        scan = dict(db.execute(
            "SELECT * FROM topology_scans WHERE device_name = 'R1'"
        ).fetchone())
    assert scan["neighbor_count"] == 1


def test_lightweight_topology_refresh_does_not_touch_mac_freshness(tmp_path):
    inventory = make_inventory(tmp_path)
    service = TopologyService(inventory, mock=True)
    service.mac_service.scan("R1", workers=1)
    with service.index.connect() as db:
        before = dict(db.execute(
            "SELECT * FROM mac_scans WHERE device_name = 'R1'"
        ).fetchone())
        macs_before = db.execute(
            "SELECT COUNT(*) FROM mac_observations WHERE device_name = 'R1'"
        ).fetchone()[0]
    result = service.discover("R1", workers=1)
    assert result["collection_status"] == "success"
    with service.index.connect() as db:
        after = dict(db.execute(
            "SELECT * FROM mac_scans WHERE device_name = 'R1'"
        ).fetchone())
        macs_after = db.execute(
            "SELECT COUNT(*) FROM mac_observations WHERE device_name = 'R1'"
        ).fetchone()[0]
    assert after == before
    assert macs_after == macs_before


def test_topology_validates_target_age_and_inventory(tmp_path):
    service = TopologyService(make_inventory(tmp_path))
    with pytest.raises(InventoryError, match="Unknown device"):
        service.get("R1;reload", 60)
    for age in (0, 10081, True):
        with pytest.raises(InventoryError, match="max_age_minutes"):
            service.get("all", age)


def test_topology_diagram_renders_text_and_mermaid(tmp_path):
    inventory = make_inventory(tmp_path)
    index = MacIndex(inventory)
    record(index, "R1", [{
        "interface": "Gi0/0", "neighbor": "SW1", "neighbor_address": "192.0.2.2",
        "remote_interface": "Gi1/0/1", "protocol": "cdp",
    }])
    record(index, "SW1", [{
        "interface": "Gi1/0/1", "neighbor": "R1", "neighbor_address": "192.0.2.1",
        "remote_interface": "Gi0/0", "protocol": "lldp",
    }])
    record(index, "EDGE", [])
    service = TopologyService(inventory)
    structured = service.diagram_data("all", "Example City", 60)
    assert "format" not in structured and "diagram" not in structured
    assert structured["location_filter"] == "Example City"
    text = service.diagram("all", "Example City", 60, "text")
    assert "[R1] Gi0/0 <==> Gi1/0/1 [SW1]" in text["diagram"]
    assert text["counts"]["nodes"] == 2
    mermaid = service.diagram("all", "Example City", 60, "mermaid")
    assert mermaid["diagram"].startswith("flowchart LR\n")
    assert "<-->" in mermaid["diagram"]
    assert "R1" in mermaid["diagram"] and "SW1" in mermaid["diagram"]


def test_topology_diagram_location_keeps_boundary_and_validates_options(tmp_path):
    inventory = make_inventory(tmp_path)
    index = MacIndex(inventory)
    record(index, "R1", [{
        "interface": "Gi0/1", "neighbor": "EDGE", "neighbor_address": "192.0.2.3",
        "remote_interface": "1/1/1", "protocol": "lldp",
    }])
    record(index, "SW1", [])
    record(index, "EDGE", [])
    service = TopologyService(inventory)
    result = service.diagram("all", "Example City", 60, "mermaid")
    scopes = {node["device"]: node["scope"] for node in result["nodes"]}
    assert scopes == {"R1": "selected", "SW1": "selected", "EDGE": "boundary"}
    assert "boundary" in result["diagram"]
    with pytest.raises(InventoryError, match="No inventory devices"):
        service.diagram("all", "Nowhere", 60, "text")
    with pytest.raises(InventoryError, match="format"):
        service.diagram("all", "", 60, "svg")
