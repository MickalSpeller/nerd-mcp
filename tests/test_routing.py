from unittest.mock import Mock

import pytest

from nerd_mcp.domain.models import (
    OspfDatabaseEvidence,
    OspfNeighborDetail,
    RouteDetail,
    RouteEvidence,
)
from nerd_mcp.inventory import Device, Inventory, InventoryError
from nerd_mcp.domain.models import CollectionResult, Interface
from nerd_mcp.routing import (
    MOCK_OSPF_DATABASE,
    MOCK_OSPF_NEIGHBORS,
    MOCK_ROUTE_OUTPUT,
    RouteTracer,
    normalize_destination,
    parse_database_router,
    parse_database_router_model,
    parse_interface_addresses,
    parse_ospf_neighbors,
    parse_ospf_neighbors_model,
    parse_route_detail,
    parse_route_detail_model,
)
from nerd_mcp.vendors.cisco.ios import routing as ios_routing
from nerd_mcp.vendors.routing import RoutingEvidenceCollector


def make_inventory(tmp_path):
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text(
        "name,host,device_type,vendor,platform\n"
        "R1,192.0.2.1,router,Cisco,IOS-XE\n"
        "R2,192.0.2.2,router,Cisco,IOS-XE\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(csv_path)
    return inventory


def test_parse_detailed_ospf_route_neighbor_and_database():
    route = parse_route_detail(MOCK_ROUTE_OUTPUT, "2.2.2.2")
    assert route["found"] and route["prefix"] == "2.2.2.2/32"
    assert route["protocol"] == "ospf 1"
    assert (route["distance"], route["metric"], route["route_type"]) == (110, 11, "intra area")
    assert route["next_hops"] == [{
        "address": "192.0.2.2",
        "interface": "GigabitEthernet1/0/1",
        "route_source_router_id": "2.2.2.2",
    }]
    assert route["route_source_router_ids"] == ["2.2.2.2"]
    neighbor = parse_ospf_neighbors(MOCK_OSPF_NEIGHBORS)[0]
    assert neighbor == {
        "router_id": "2.2.2.2", "address": "192.0.2.2",
        "interface": "GigabitEthernet1/0/1", "area": "0", "state": "FULL",
    }
    database = parse_database_router(MOCK_OSPF_DATABASE, "2.2.2.2")
    assert database["verified"] and database["advertising_router_ids"] == ["2.2.2.2"]


def test_routing_parsers_expose_typed_domain_contracts():
    route = parse_route_detail_model(MOCK_ROUTE_OUTPUT, "2.2.2.2")
    neighbors = parse_ospf_neighbors_model(MOCK_OSPF_NEIGHBORS)
    database = parse_database_router_model(MOCK_OSPF_DATABASE, "2.2.2.2")

    assert isinstance(route, RouteDetail)
    assert route.next_hops[0].address == "192.0.2.2"
    assert isinstance(neighbors[0], OspfNeighborDetail)
    assert isinstance(database, OspfDatabaseEvidence)
    assert database.verified


def test_root_routing_parsers_are_vendor_compatibility_aliases():
    assert parse_route_detail is ios_routing.parse_route_detail
    assert parse_route_detail_model is ios_routing.parse_route_detail_model
    assert parse_ospf_neighbors is ios_routing.parse_ospf_neighbors
    assert parse_database_router is ios_routing.parse_database_router


def test_routing_evidence_collector_returns_typed_vendor_results(tmp_path):
    inventory = make_inventory(tmp_path)
    reader = Mock()
    reader.read_many.return_value = ({
        "route": MOCK_ROUTE_OUTPUT,
        "neighbors": MOCK_OSPF_NEIGHBORS,
    }, None)
    reader.read.return_value = (MOCK_OSPF_DATABASE, None)
    collector = RoutingEvidenceCollector(inventory, False, reader)

    route = collector.collect_route("R1", "2.2.2.2")
    database = collector.collect_database("R1", "router", "2.2.2.2")

    assert isinstance(route, RouteEvidence)
    assert route.route.next_hops[0].address == "192.0.2.2"
    assert route.neighbors[0].router_id == "2.2.2.2"
    assert database.evidence.verified
    assert database.command == "show ip ospf database router 2.2.2.2"


def test_routing_evidence_preserves_partial_and_unsupported_boundaries(tmp_path):
    inventory = make_inventory(tmp_path)
    reader = Mock()
    reader.read_many.return_value = ({
        "route": MOCK_ROUTE_OUTPUT,
        "neighbors": "% Invalid input",
    }, None)
    reader.read.return_value = ("% Invalid input", None)
    collector = RoutingEvidenceCollector(inventory, False, reader)

    route = collector.collect_route("R1", "2.2.2.2")
    database = collector.collect_database("R1", "router", "2.2.2.2")
    assert route.route.found and not route.neighbors and route.warnings
    assert not database.evidence.verified and database.warnings

    unsupported_inventory = Mock()
    unsupported_inventory.get.return_value = Device(
        "J1", "192.0.2.10", vendor="Juniper", platform="Junos"
    )
    unsupported_reader = Mock()
    unsupported = RoutingEvidenceCollector(
        unsupported_inventory, False, unsupported_reader
    )
    with pytest.raises(InventoryError):
        unsupported.collect_route("J1", "2.2.2.2")
    unsupported_reader.read_many.assert_not_called()


def test_parse_compact_route_and_interface_addresses():
    route = parse_route_detail(
        "O 2.2.2.2/32 [110/11] via 10.0.12.2, 00:01:20, Ethernet0/1.12",
        "2.2.2.2",
    )
    assert route["found"] and route["next_hops"][0]["address"] == "10.0.12.2"
    assert route["next_hops"][0]["interface"] == "Ethernet0/1.12"
    addresses = parse_interface_addresses(
        "Interface IP-Address OK? Method Status Protocol\n"
        "Ethernet0/1.12 10.0.12.2 YES manual up up\n"
        "Ethernet0/2 unassigned YES unset administratively down down"
    )
    assert addresses == [{
        "interface": "Ethernet0/1.12", "address": "10.0.12.2",
        "status": "up", "protocol": "up",
    }]


@pytest.mark.parametrize("value", ["reload", "2.2.2.2;reload", "2001:db8::1", "224.0.0.5", "0.0.0.0"])
def test_destination_validation_rejects_non_unicast_ipv4(value):
    with pytest.raises(InventoryError):
        normalize_destination(value)


def test_mock_trace_resolves_next_hop_and_advertising_device(tmp_path):
    result = RouteTracer(make_inventory(tmp_path), mock=True).trace("R1", "2.2.2.2", workers=2)
    assert result["status"] == "success" and result["route_found"] and result["is_ospf"]
    assert result["next_hops"][0]["device"] == "R2"
    assert result["next_hops"][0]["neighbor_router_id"] == "2.2.2.2"
    assert result["advertising_router_id"] == "2.2.2.2"
    assert result["advertising_device"] == "R2"
    assert result["complete"] and result["confidence"] == "high"
    assert result["commands"] == [
        "show ip route 2.2.2.2",
        "show ip ospf neighbor detail",
        "show ip ospf database router 2.2.2.2",
    ]
    assert "Routing entry" not in str(result["inventory_checks"])


def test_invalid_trace_inputs_never_connect(tmp_path):
    inventory = make_inventory(tmp_path)
    connector = Mock()
    tracer = RouteTracer(inventory, connector=connector)
    for destination in ("2.2.2.2; reload", "not-an-address"):
        assert tracer.trace("R1", destination)["status"] == "error"
    assert tracer.trace("missing", "2.2.2.2")["status"] == "error"
    for workers in (0, 17, True):
        assert tracer.trace("R1", "2.2.2.2", workers)["status"] == "error"
    connector.assert_not_called()


def test_inventory_connection_failure_keeps_mapping_but_lowers_confidence(tmp_path):
    inventory = make_inventory(tmp_path)
    fake_network = Mock()
    fake_network.read_many.return_value = ({
        "route": MOCK_ROUTE_OUTPUT, "neighbors": MOCK_OSPF_NEIGHBORS,
    }, None)
    fake_network.read.return_value = (MOCK_OSPF_DATABASE, None)

    def collect_interfaces(name):
        result = CollectionResult(name, "interfaces", "2026-09-10T00:00:00+00:00", "live")
        if name == "R2":
            result.error = "SSH connection timed out."
        else:
            result.status = "success"
            result.complete = True
            result.data = (Interface("Ethernet0/0", "192.0.2.1", "up", "up"),)
        return result

    fake_network.collect_interfaces.side_effect = collect_interfaces
    tracer = RouteTracer(
        inventory, network=fake_network, command_reader=fake_network
    )
    result = tracer.trace("R1", "2.2.2.2", 1)
    assert result["advertising_device"] == "R2"  # Inventory host still provides a candidate.
    assert not result["complete"] and result["confidence"] == "medium"
    assert result["incomplete_devices"] == [{
        "device": "R2", "error": "SSH connection timed out.",
    }]
