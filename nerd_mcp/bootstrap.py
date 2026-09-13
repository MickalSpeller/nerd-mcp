"""Composition root for NERD application services and owned resources."""

from __future__ import annotations

from dataclasses import dataclass, field

from .application.baselines import BaselineQueryService, BaselineWriteService
from .application.changes import ChangePlanningService, ChangeQueryService, ChangeWriteService
from .application.diagnosis import DiagnosisService
from .application.baseline_workflow import ConfigurationBaselineWorkflow
from .application.endpoint import EndpointWorkflow
from .application.health import FleetHealthService
from .application.inspection import NetworkWorkflow
from .application.inventory import InventoryRefreshService
from .application.mac import MacWorkflow
from .application.pathing import MacPathWorkflow
from .application.routing import RouteTracingWorkflow
from .application.topology import TopologyWorkflow
from .application.workflows import (
    EndpointResolutionService,
    MacObservationService,
    MacPathApplicationService,
    NetworkInspectionService,
    RouteTracingService,
    TopologyApplicationService,
)
from .inventory import Inventory
from .ssh_pool import SSHConnectionPool
from .storage.baselines_sqlite import BaselineRepository
from .storage.changes_sqlite import ChangeRepository
from .storage.diagnoses_sqlite import DiagnosisRepository
from .storage.observations_sqlite import ObservationRepository
from .topology_rendering import TopologyDiagramPresenter
from .transport.netmiko import NetmikoSessionFactory, NetmikoTransport
from .transport.errors import safe_device_error
from .vendors.commands import command_error
from .vendors.change_adapters import adapter_for_platform as change_adapter_for_platform
from .vendors.registry import CAPABILITIES
from .vendors.routing import RoutingEvidenceCollector


@dataclass
class Application:
    """One consistently wired set of application services.

    The application owns its optional connection pool. ``close`` is idempotent so
    adapter cleanup and the MCP lifespan can safely converge on the same boundary.
    """

    inventory: Inventory
    mock: bool
    network: NetworkInspectionService
    inventory_refresh: InventoryRefreshService
    fleet_health: FleetHealthService
    mac: MacObservationService
    routing: RouteTracingService
    routing_evidence: RoutingEvidenceCollector
    baselines: BaselineQueryService
    baseline_writes: BaselineWriteService
    topology: TopologyApplicationService
    mac_paths: MacPathApplicationService
    endpoints: EndpointResolutionService
    session_factory: NetmikoSessionFactory
    transport: NetmikoTransport
    observations: ObservationRepository
    baseline_repository: BaselineRepository
    change_planning: ChangePlanningService
    changes: ChangeQueryService
    change_writes: ChangeWriteService
    change_repository: ChangeRepository
    diagnoses: DiagnosisService | None
    diagnosis_repository: DiagnosisRepository
    ssh_pool: SSHConnectionPool | None = None
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.ssh_pool is not None:
            self.ssh_pool.close_all()

    def __enter__(self) -> Application:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def build_application(inventory: Inventory, mock: bool = False, *,
                      pooled: bool = False, connector=None) -> Application:
    """Build the service graph for a terminal command or long-running adapter.

    Direct terminal commands use short-lived transport sessions. Long-running
    adapters request a pool, which this application then owns and closes.
    """
    session_factory = NetmikoSessionFactory(connector=connector)
    ssh_pool = (
        SSHConnectionPool(
            register_atexit=False, session_factory=session_factory
        )
        if pooled else None
    )
    transport = NetmikoTransport(
        connection_pool=ssh_pool, session_factory=session_factory
    )
    observations = ObservationRepository(inventory)
    baseline_repository = BaselineRepository(inventory)
    change_repository = ChangeRepository(inventory)
    diagnosis_repository = DiagnosisRepository(inventory)
    network_workflow = NetworkWorkflow(
        inventory, mock, transport, CAPABILITIES,
        safe_device_error, command_error,
    )
    network = NetworkInspectionService(network_workflow)
    mac_workflow = MacWorkflow(
        inventory, mock, observations, transport, CAPABILITIES,
        safe_device_error, command_error,
    )
    mac = MacObservationService(mac_workflow)
    topology_workflow = TopologyWorkflow(
        inventory, mock, mac, observations, CAPABILITIES
    )
    topology = TopologyApplicationService(
        topology_workflow, TopologyDiagramPresenter()
    )
    mac_path_workflow = MacPathWorkflow(inventory, mock, mac, topology)
    mac_paths = MacPathApplicationService(mac_path_workflow)
    baselines = ConfigurationBaselineWorkflow(
        inventory, mock, network, baseline_repository, safe_device_error
    )
    routing_evidence = RoutingEvidenceCollector(inventory, mock, network)
    route_workflow = RouteTracingWorkflow(
        inventory, mock, network, routing_evidence, CAPABILITIES,
        safe_device_error,
    )
    endpoint_workflow = EndpointWorkflow(inventory, mock, mac, mac_paths)
    change_planning = ChangePlanningService(
        inventory, change_repository, transport, CAPABILITIES,
        change_adapter_for_platform, command_error, safe_device_error, mock
    )
    changes = ChangeQueryService(change_repository)
    change_writes = ChangeWriteService(
        inventory, change_repository, transport, CAPABILITIES, command_error,
        safe_device_error, mock
    )
    diagnosis = DiagnosisService(
        inventory, network, change_planning, diagnosis_repository, model=""
    )
    return Application(
        inventory=inventory,
        mock=mock,
        network=network,
        inventory_refresh=InventoryRefreshService(inventory, network),
        fleet_health=FleetHealthService(inventory, network),
        mac=mac,
        routing=RouteTracingService(route_workflow),
        routing_evidence=routing_evidence,
        baselines=BaselineQueryService(baselines),
        baseline_writes=BaselineWriteService(inventory, baselines),
        topology=topology,
        mac_paths=mac_paths,
        endpoints=EndpointResolutionService(endpoint_workflow),
        session_factory=session_factory,
        transport=transport,
        observations=observations,
        baseline_repository=baseline_repository,
        change_planning=change_planning,
        changes=changes,
        change_writes=change_writes,
        change_repository=change_repository,
        diagnoses=diagnosis,
        diagnosis_repository=diagnosis_repository,
        ssh_pool=ssh_pool,
    )
