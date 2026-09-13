"""Storage and topology-rendering boundary coverage."""

from pathlib import Path

from nerd_mcp.domain.inventory import Device
from nerd_mcp.inventory import Inventory
from nerd_mcp.mac import MacIndex
from nerd_mcp.snapshots import ConfigurationBaselines
from nerd_mcp.storage.baselines_sqlite import BaselineRepository
from nerd_mcp.storage.inventory_sqlite import InventoryRepository
from nerd_mcp.storage.importers import load_inventory_import
from nerd_mcp.storage.observations_sqlite import ObservationRepository
from nerd_mcp.topology import TopologyService
from nerd_mcp.topology_rendering import (
    escape_mermaid_text,
    render_mermaid_topology,
    render_text_topology,
)


def test_historical_mac_index_name_forwards_to_storage_repository(tmp_path):
    inventory = Inventory(tmp_path / "inventory.db")
    assert MacIndex is ObservationRepository
    assert isinstance(MacIndex(inventory), ObservationRepository)


def test_historical_inventory_name_forwards_to_sqlite_repository(tmp_path):
    inventory = Inventory(tmp_path / "inventory.db")
    assert Inventory is InventoryRepository
    assert isinstance(inventory, InventoryRepository)
    assert Device.__module__ == "nerd_mcp.domain.inventory"


def test_mac_service_module_no_longer_owns_sql_schema():
    source = (Path(__file__).parents[1] / "nerd_mcp" / "mac.py").read_text(encoding="utf-8")
    assert "CREATE TABLE" not in source
    assert "sqlite3" not in source
    assert ".connect()" not in source


def test_observation_repository_no_longer_owns_mac_policy():
    source = (
        Path(__file__).parents[1]
        / "nerd_mcp"
        / "storage"
        / "observations_sqlite.py"
    ).read_text(encoding="utf-8")
    assert "def locate(" not in source
    assert "def locate_ip(" not in source
    assert "def troubleshoot(" not in source
    assert '"confidence"' not in source


def test_workflow_modules_no_longer_own_inventory_or_baseline_sql():
    root = Path(__file__).parents[1] / "nerd_mcp"
    inventory_source = (root / "inventory.py").read_text(encoding="utf-8")
    snapshots_source = (root / "snapshots.py").read_text(encoding="utf-8")
    assert "CREATE TABLE" not in inventory_source
    assert "sqlite3" not in inventory_source
    assert "CREATE TABLE" not in snapshots_source
    assert "db.execute" not in snapshots_source


def test_inventory_file_importer_is_independent_from_sqlite(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,Location,Country\ncore,192.0.2.1,Example City,usa\n",
        encoding="utf-8-sig",
    )
    batch = load_inventory_import(source)
    assert batch.records[0].row_number == 2
    assert batch.records[0].device.location == "Example City"
    assert batch.records[0].device.country == "USA"
    assert batch.metadata_fields == frozenset({"location", "country"})

    root = Path(__file__).parents[1] / "nerd_mcp"
    importer_source = (root / "storage" / "importers.py").read_text(encoding="utf-8")
    repository_source = (root / "storage" / "inventory_sqlite.py").read_text(
        encoding="utf-8"
    )
    assert "sqlite3" not in importer_source
    assert "csv.reader" not in repository_source
    assert "openpyxl" not in repository_source


def test_baseline_service_accepts_an_injected_repository(tmp_path):
    class EmptyRepository:
        @staticmethod
        def list():
            return []

    service = ConfigurationBaselines(
        Inventory(tmp_path / "inventory.db"), network=object(), repository=EmptyRepository()
    )
    assert service.list() == {"status": "success", "count": 0, "baselines": []}
    assert isinstance(BaselineRepository(service.inventory), BaselineRepository)


def test_topology_renderer_escapes_labels_and_keeps_compatibility_aliases():
    assert escape_mermaid_text('edge<&|"') == "edge&lt;&amp;&#124;&quot;"
    assert TopologyService._mermaid_diagram is render_mermaid_topology
    assert TopologyService._text_diagram is render_text_topology


def test_topology_service_module_no_longer_owns_rendering_grammar():
    source = (Path(__file__).parents[1] / "nerd_mcp" / "topology.py").read_text(encoding="utf-8")
    assert 'lines = ["flowchart LR"]' not in source
    assert "classDef router" not in source
    assert "db.execute" not in source
    assert ".connect()" not in source
