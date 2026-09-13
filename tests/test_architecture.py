import ast
from pathlib import Path

from nerd_mcp.domain.errors import (
    InventoryError as DomainInventoryError,
    MissingBaselineError as DomainMissingBaselineError,
    UnsupportedCapability as DomainUnsupportedCapability,
)
from nerd_mcp.domain.ports import (
    BaselineRepositoryPort,
    CapabilityProviderPort,
    CommandCollectionPort,
    DeviceTransportPort,
    DeviceSessionFactoryPort,
    EndpointResolutionPort,
    InspectionWorkflowPort,
    InventoryPort,
    MacObservationPort,
    MacPathPort,
    NetworkPort,
    ObservationRepositoryPort,
    RouteTracingPort,
    RoutingEvidencePort,
    TopologyDiagramPresenterPort,
    TopologyPort,
    TopologyWorkflowPort,
)
from nerd_mcp.bootstrap import build_application
from nerd_mcp.inventory import Inventory, InventoryError
from nerd_mcp.application.baseline_workflow import ConfigurationBaselineWorkflow
from nerd_mcp.application.endpoint import EndpointWorkflow
from nerd_mcp.application.inspection import NetworkWorkflow
from nerd_mcp.application.mac import MacWorkflow
from nerd_mcp.application.pathing import MacPathWorkflow
from nerd_mcp.application.routing import RouteTracingWorkflow
from nerd_mcp.application.topology import TopologyWorkflow
from nerd_mcp.network import Network
from nerd_mcp.snapshots import MissingBaselineError
from nerd_mcp.storage.baselines_sqlite import BaselineRepository
from nerd_mcp.storage.observations_sqlite import ObservationRepository
from nerd_mcp.transport.netmiko import NetmikoSessionFactory, NetmikoTransport
from nerd_mcp.vendors.registry import UnsupportedCapability
from nerd_mcp.vendors.registry import CAPABILITIES
from nerd_mcp.vendors.routing import RoutingEvidenceCollector


PACKAGE = Path(__file__).parents[1] / "nerd_mcp"


def _package_imports(path: Path) -> set[str]:
    imports = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names if alias.name.startswith("nerd_mcp"))
        elif isinstance(node, ast.ImportFrom):
            if node.level >= 2:
                imports.add(f"parent:{node.module or ''}")
            elif node.level == 0 and (node.module or "").startswith("nerd_mcp"):
                imports.add(node.module or "")
    return imports


def test_domain_does_not_import_outer_package_layers():
    violations = {
        path.name: sorted(_package_imports(path))
        for path in (PACKAGE / "domain").glob("*.py")
        if _package_imports(path)
    }
    assert violations == {}


def test_application_does_not_import_adapters_or_infrastructure():
    forbidden = (
        "storage", "transport", "vendors", "terminal", "server", "chat", "openai",
    )
    violations = {}
    for path in (PACKAGE / "application").glob("*.py"):
        matches = [name for name in _package_imports(path) if any(part in name for part in forbidden)]
        if matches:
            violations[path.name] = matches
    assert violations == {}


def test_application_workflow_cores_do_not_import_historical_root_workflows():
    compatibility_modules = {
        "nerd_mcp.endpoint", "nerd_mcp.mac", "nerd_mcp.network",
        "nerd_mcp.pathing", "nerd_mcp.routing", "nerd_mcp.snapshots",
        "nerd_mcp.topology",
    }
    violations = {
        path.name: sorted(_package_imports(path) & compatibility_modules)
        for path in (PACKAGE / "application").glob("*.py")
        if _package_imports(path) & compatibility_modules
    }
    assert violations == {}


def test_compatibility_errors_are_domain_errors():
    assert InventoryError is DomainInventoryError
    assert MissingBaselineError is DomainMissingBaselineError
    assert UnsupportedCapability is DomainUnsupportedCapability


def test_composition_objects_satisfy_domain_ports(tmp_path):
    inventory = Inventory(tmp_path / "inventory.db")
    network = Network(inventory, mock=True)
    observations = ObservationRepository(inventory)
    baselines = BaselineRepository(inventory)

    assert isinstance(inventory, InventoryPort)
    assert isinstance(network, NetworkPort)
    assert isinstance(network, CommandCollectionPort)
    assert isinstance(NetmikoTransport(), DeviceTransportPort)
    assert isinstance(NetmikoSessionFactory(), DeviceSessionFactoryPort)
    assert isinstance(CAPABILITIES, CapabilityProviderPort)
    assert isinstance(observations, ObservationRepositoryPort)
    assert isinstance(baselines, BaselineRepositoryPort)


def test_bootstrap_exposes_application_workflow_ports(tmp_path):
    application = build_application(Inventory(tmp_path / "application.db"), mock=True)

    assert isinstance(application.network, InspectionWorkflowPort)
    assert isinstance(application.mac, MacObservationPort)
    assert isinstance(application.routing, RouteTracingPort)
    assert isinstance(application.routing_evidence, RoutingEvidencePort)
    assert type(application.routing_evidence) is RoutingEvidenceCollector
    assert isinstance(application.topology, TopologyPort)
    assert isinstance(application.topology._workflow, TopologyWorkflowPort)
    assert isinstance(application.topology._presenter, TopologyDiagramPresenterPort)
    assert isinstance(application.mac_paths, MacPathPort)
    assert isinstance(application.endpoints, EndpointResolutionPort)

    assert isinstance(application.network._workflow, NetworkWorkflow)
    assert type(application.mac._workflow) is MacWorkflow
    assert type(application.routing._workflow) is RouteTracingWorkflow
    assert type(application.baselines._baselines) is ConfigurationBaselineWorkflow
    assert type(application.topology._workflow) is TopologyWorkflow
    assert type(application.mac_paths._workflow) is MacPathWorkflow
    assert type(application.endpoints._workflow) is EndpointWorkflow
    assert application.network._workflow.transport is application.transport
    assert application.mac._workflow.transport is application.transport
    assert application.network._workflow.capabilities is CAPABILITIES
    assert application.mac._workflow.capabilities is CAPABILITIES
    assert application.topology._workflow.capabilities is CAPABILITIES
    assert application.routing._workflow.capabilities is CAPABILITIES


def test_interface_adapters_do_not_import_compatibility_workflows():
    compatibility_modules = {
        "nerd_mcp.endpoint", "nerd_mcp.mac", "nerd_mcp.network",
        "nerd_mcp.pathing", "nerd_mcp.routing", "nerd_mcp.snapshots",
        "nerd_mcp.topology",
    }
    violations = {
        path.name: sorted(_package_imports(path) & compatibility_modules)
        for path in (
            PACKAGE / "cli.py", PACKAGE / "chat.py", PACKAGE / "local_executor.py",
            PACKAGE / "server.py",
        )
        if _package_imports(path) & compatibility_modules
    }
    assert violations == {}


def test_local_and_mcp_adapters_share_application_tool_dispatch():
    for name in ("local_executor.py", "server.py"):
        source = (PACKAGE / name).read_text(encoding="utf-8")
        assert "from .application.tool_execution import execute_tool" in source
        tree = ast.parse(source)
        assert any(
            isinstance(node, ast.Name) and node.id == "execute_tool"
            for node in ast.walk(tree)
        )
