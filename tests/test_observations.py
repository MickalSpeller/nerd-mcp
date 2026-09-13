"""Typed observation boundaries using synthetic output and temporary databases."""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import re

import pytest

from nerd_mcp.domain.models import (
    ArpObservation,
    InterfaceHealthObservation,
    MacObservation,
    NeighborObservation,
    ObservationBatch,
)
from nerd_mcp.domain.normalization import interface_key, normalize_interface, normalize_mac
from nerd_mcp.transport.errors import safe_device_error
from nerd_mcp.vendors.commands import command_error
from nerd_mcp.inventory import Device, Inventory, InventoryError
from nerd_mcp.mac import MacIndex, MacService, adapter_for
from nerd_mcp.vendors.cisco import observations as cisco
from nerd_mcp.vendors.aruba.aoscx import collector as aoscx
from nerd_mcp.vendors.aruba.aosswitch import collector as aosswitch
from nerd_mcp.vendors.fortinet.fortios import observations as fortios
from nerd_mcp.vendors.registry import platform_for


@pytest.mark.parametrize("device,module", [
    (Device("ios", "192.0.2.1", vendor="Cisco", platform="IOS-XE"), cisco),
    (Device("nx", "192.0.2.2", vendor="Cisco", platform="NX-OS"), cisco),
    (Device("cx", "192.0.2.3", vendor="Aruba", platform="AOS-CX"), aoscx),
    (Device("aos", "192.0.2.4", vendor="Aruba", platform="AOS-Switch"), aosswitch),
    (Device("fw", "192.0.2.5", vendor="Fortinet", platform="FortiOS"), fortios),
])
def test_registry_owns_observation_adapter(device, module):
    platform = platform_for(device)
    adapter = adapter_for(device)
    assert platform.observation_collector is module
    assert adapter.collector is module
    assert adapter.commands is module.COMMANDS
    assert adapter.netmiko_type == platform.driver


@pytest.mark.parametrize("module", [cisco, aoscx, aosswitch, fortios])
def test_vendor_fixtures_produce_typed_observation_batches(module):
    batch = module.parse_observations(module.MOCK_OUTPUTS)
    assert isinstance(batch, ObservationBatch)
    assert all(isinstance(row, MacObservation) for row in batch.macs)
    assert all(isinstance(row, ArpObservation) for row in batch.arps)
    assert all(isinstance(row, NeighborObservation) for row in batch.neighbors)
    assert all(isinstance(row, InterfaceHealthObservation) for row in batch.interfaces)
    assert all(isinstance(value, str) for row in batch.macs for value in asdict(row).values())


def test_public_normalization_and_error_helpers_preserve_contracts():
    assert normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert normalize_interface("Ethernet1/1") == interface_key("e1/1") == "e1/1"
    assert command_error("% Invalid input detected")
    assert not command_error("show output")
    error = InventoryError("safe message")
    assert safe_device_error(error) == "safe message"


def test_index_serializes_typed_rows_without_schema_changes(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(source)
    index = MacIndex(inventory)
    timestamp = datetime.now(timezone.utc).isoformat()
    index.replace(
        "core", timestamp, "success", None,
        [MacObservation("00:11:22:33:44:55", "20", "Gi1/0/18", "dynamic", "access")],
        [ArpObservation("00:11:22:33:44:55", "10.20.0.45", "Vlan20")],
        [NeighborObservation("Gi1/0/48", "dist", "192.0.2.2", "Gi1/0/1", "cdp")],
        [InterfaceHealthObservation("Gi1/0/18", "up", "up", "endpoint")],
        mock=True,
    )
    with index.connect() as db:
        assert [row["name"] for row in db.execute("PRAGMA table_info(mac_observations)")] == [
            "device_name", "mac", "vlan", "interface", "interface_key",
            "entry_type", "role", "observed_at",
        ]
        mac = dict(db.execute("SELECT * FROM mac_observations").fetchone())
        arp = dict(db.execute("SELECT * FROM arp_observations").fetchone())
        neighbor = dict(db.execute("SELECT * FROM mac_neighbors").fetchone())
    assert mac["interface_key"] == "gi1/0/18" and mac["role"] == "access"
    assert arp["vrf"] == "default"
    assert neighbor["neighbor_address"] == "192.0.2.2"


def test_source_consumers_no_longer_import_private_mac_or_network_helpers():
    root = Path(__file__).parents[1] / "nerd_mcp"
    for name in ("endpoint.py", "pathing.py", "routing.py", "snapshots.py", "topology.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert not re.search(r"(?m)^from \.mac import .*\b_interface_key\b", source)
        assert not re.search(r"(?m)^from \.network import .*\b_safe_error\b", source)
        assert not re.search(r"(?m)^from \.network import .*\b_command_error\b", source)


def test_mock_service_classifies_typed_observations_before_storage(tmp_path, monkeypatch):
    source = tmp_path / "devices.csv"
    source.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(source)
    captured = {}
    service = MacService(inventory, mock=True)
    original = service.index.replace

    def capture(device, timestamp, status, error, macs, arps, neighbors, interfaces, mock=False):
        captured.update(macs=macs, arps=arps, neighbors=neighbors, interfaces=interfaces)
        return original(device, timestamp, status, error, macs, arps, neighbors, interfaces, mock)

    monkeypatch.setattr(service.index, "replace", capture)
    result = service.scan("core", 1)
    assert result["status"] == "success"
    assert all(isinstance(row, MacObservation) for row in captured["macs"])
    assert captured["macs"][0].role == "access"
    assert all(isinstance(row, ArpObservation) for row in captured["arps"])
    assert all(isinstance(row, NeighborObservation) for row in captured["neighbors"])
    assert all(isinstance(row, InterfaceHealthObservation) for row in captured["interfaces"])
