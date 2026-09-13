"""Application behavior with injected collectors and temporary inventory."""
from types import SimpleNamespace
from unittest.mock import Mock, call
import sqlite3

import pytest

from nerd_mcp.application.health import FleetHealthService
from nerd_mcp.application.inventory import InventoryRefreshService
from nerd_mcp.application.workflows import MacObservationService
from nerd_mcp.inventory import Inventory, InventoryError


@pytest.fixture
def inventory(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_text("name,host,location\na,192.0.2.1,Operator\nb,192.0.2.2,\nc,192.0.2.3,\n")
    inventory = Inventory(tmp_path / "inventory.db")
    inventory.import_csv(source)
    return inventory


def test_refresh_order_partial_results_and_location_precedence(inventory):
    responses = [{"status": "success", "facts": {"model": "A", "location": "Device"}},
                 {"status": "error", "error": "unavailable"},
                 {"status": "success", "facts": {"model": "C"}}]
    network = Mock()
    network.discover_inventory.side_effect = responses
    service = InventoryRefreshService(inventory, network)
    assert service.refresh("aLl") == responses
    assert [c.args[0] for c in network.discover_inventory.call_args_list] == ["a", "b", "c"]
    assert service.successful_discoveries == 2
    assert inventory.get("a").location == "Operator"
    assert inventory.get("b").model == ""
    assert inventory.get("c").model == "C"
    assert "record" not in responses[1]


def test_refresh_write_error_aborts_and_preserves_prior_writes(inventory, monkeypatch):
    original = inventory.update_facts
    failure = sqlite3.OperationalError("unavailable")
    def update(name, facts):
        if name == "b":
            raise failure
        return original(name, facts)
    monkeypatch.setattr(inventory, "update_facts", update)
    network = Mock()
    network.discover_inventory.side_effect = [
        {"status": "success", "facts": {"model": "A"}},
        {"status": "success", "facts": {"model": "B"}},
    ]
    service = InventoryRefreshService(inventory, network)
    with pytest.raises(sqlite3.OperationalError) as error:
        service.refresh("all")
    assert error.value is failure
    assert inventory.get("a").model == "A"
    assert inventory.get("b").model == ""
    assert network.discover_inventory.call_count == 2
    assert service.successful_discoveries == 2
    network.discover_inventory.side_effect = None
    network.discover_inventory.return_value = {"status": "error"}
    service.refresh("c")
    assert service.successful_discoveries == 0


@pytest.mark.parametrize("service_type, method, collector", [
    (InventoryRefreshService, "refresh", "discover_inventory"),
    (FleetHealthService, "check", "health"),
])
def test_single_target_and_collector_exception(inventory, service_type, method, collector):
    network = Mock()
    response = {"status": "error", "error": "unknown device"}
    getattr(network, collector).return_value = response
    service = service_type(inventory, network)
    assert getattr(service, method)("missing") == [response]
    getattr(network, collector).assert_called_once_with("missing")
    failure = RuntimeError("collector stopped")
    getattr(network, collector).side_effect = failure
    with pytest.raises(RuntimeError) as error:
        getattr(service, method)("a")
    assert error.value is failure


def test_empty_fleet_behaviors():
    inventory, network = Mock(), Mock()
    inventory.list.return_value = []
    assert InventoryRefreshService(inventory, network).refresh("ALL") == []
    with pytest.raises(InventoryError, match="No devices are inventoried"):
        FleetHealthService(inventory, network).check("ALL")
    assert network.mock_calls == []


def test_health_preserves_order_and_results_without_writes():
    inventory, network = Mock(), Mock()
    inventory.list.return_value = [SimpleNamespace(name="b"), SimpleNamespace(name="a")]
    responses = [{"status": "error"}, {"status": "success", "overall": "critical"}]
    network.health.side_effect = responses
    assert FleetHealthService(inventory, network).check("aLl") == responses
    assert [c.args[0] for c in network.health.call_args_list] == ["b", "a"]
    assert inventory.mock_calls == [call.list()]


@pytest.mark.parametrize("status", ["not_scanned", "stale"])
def test_mac_lookup_collects_when_observations_are_missing_or_stale(status):
    workflow = Mock()
    workflow.locate.side_effect = [
        {"found": False, "incomplete_devices": [{"status": status}]},
        {"found": True, "incomplete_devices": []},
    ]
    workflow.scan.return_value = {"counts": {"success": 2}}
    notices = []

    result = MacObservationService(workflow).locate_current(
        "0011.2233.4455", 15, 2,
        on_collection=lambda reason, target: notices.append((reason, target)),
    )

    assert result["found"] is True
    assert result["refreshed"] is True
    assert result["refresh_reason"] == "missing_or_stale"
    assert result["collection_counts"] == {"success": 2}
    assert notices == [("missing_or_stale", "all")]
    assert workflow.mock_calls == [
        call.locate("0011.2233.4455", 15),
        call.scan("all", 2),
        call.locate("0011.2233.4455", 15),
    ]


def test_mac_lookup_does_not_retry_failed_or_current_observations():
    workflow = Mock()
    workflow.locate.side_effect = [
        {"found": False, "incomplete_devices": [{"status": "error"}]},
        {
            "found": False,
            "incomplete_devices": [{"status": "stale", "error": "SSH failed"}],
        },
        {"found": True, "incomplete_devices": []},
    ]
    service = MacObservationService(workflow)

    failed = service.locate_current("0011.2233.4455")
    stale_after_failure = service.locate_current("0011.2233.4455")
    current = service.locate_current("0011.2233.4455")

    assert failed["refreshed"] is False
    assert stale_after_failure["refreshed"] is False
    assert current["refreshed"] is False
    workflow.scan.assert_not_called()


def test_mac_port_forced_collection_targets_only_requested_device():
    workflow = Mock()
    workflow.interface_macs.side_effect = [
        {"complete": True, "scan_status": "success"},
        {"complete": True, "scan_status": "success"},
    ]
    workflow.scan.return_value = {"counts": {"success": 1}}

    result = MacObservationService(workflow).interface_macs_current(
        "SW1", "Gi1/0/1", 15, 3, force_refresh=True,
    )

    assert result["refreshed"] is True
    assert result["refresh_reason"] == "forced"
    workflow.scan.assert_called_once_with("SW1", 3)


def test_device_mac_table_collects_only_requested_device_when_missing():
    workflow = Mock()
    workflow.device_macs.side_effect = [
        {"complete": False, "scan_status": "not_scanned", "error": None},
        {"complete": True, "scan_status": "success", "error": None},
    ]
    workflow.scan.return_value = {"counts": {"success": 1}}
    notices = []

    result = MacObservationService(workflow).device_macs_current(
        "SW1", 15, 2, on_collection=lambda reason, target: notices.append((reason, target)),
    )

    assert result["refreshed"] is True
    assert result["refresh_reason"] == "missing_or_stale"
    assert notices == [("missing_or_stale", "SW1")]
    workflow.scan.assert_called_once_with("SW1", 2)


def test_device_arp_table_collects_only_requested_device_when_missing():
    workflow = Mock()
    workflow.device_arps.side_effect = [
        {"complete": False, "scan_status": "not_scanned", "error": None},
        {"complete": True, "scan_status": "success", "error": None},
    ]
    workflow.scan.return_value = {"counts": {"success": 1}}
    notices = []

    result = MacObservationService(workflow).device_arps_current(
        "R1", 15, 2, on_collection=lambda reason, target: notices.append((reason, target)),
    )

    assert result["refreshed"] is True
    assert result["refresh_reason"] == "missing_or_stale"
    assert notices == [("missing_or_stale", "R1")]
    workflow.scan.assert_called_once_with("R1", 2)
