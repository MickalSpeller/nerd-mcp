"""Compatibility exports for application-owned OSPF route tracing."""

from .application.routing import (
    RouteTracingWorkflow as _ApplicationRouteTracingWorkflow,
    normalize_destination,
)
from .domain.ports import CommandCollectionPort, InventoryReader, NetworkPort, RoutingEvidencePort
from .network import Network
from .transport.errors import safe_device_error
from .vendors.registry import CAPABILITIES
from .vendors.routing import RoutingEvidenceCollector
from .vendors.cisco.ios.collector import parse_interface_addresses
from .vendors.cisco.ios.routing import (
    MOCK_OSPF_DATABASE,
    MOCK_OSPF_NEIGHBORS,
    MOCK_ROUTE_OUTPUT,
    parse_database_router,
    parse_database_router_model,
    parse_ospf_neighbors,
    parse_ospf_neighbors_model,
    parse_route_detail,
    parse_route_detail_model,
    valid_ipv4,
)

MAX_TRACE_OUTPUT = 100_000
_valid_ipv4 = valid_ipv4


class RouteTracingWorkflow(_ApplicationRouteTracingWorkflow):
    """Historical constructor over the application-owned workflow."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 network: NetworkPort, routing_collector: RoutingEvidencePort,
                 capability_provider=CAPABILITIES):
        super().__init__(
            inventory, mock, network, routing_collector,
            capability_provider, safe_device_error,
        )


class RouteTracer(RouteTracingWorkflow):
    """Compatibility facade for historical direct construction."""

    def __init__(self, inventory: InventoryReader, mock: bool = False, connector=None,
                 connection_pool=None, network: NetworkPort | None = None,
                 command_reader: CommandCollectionPort | None = None):
        compatibility_network = network or Network(
            inventory, mock, connector=connector, connection_pool=connection_pool
        )
        compatibility_reader = command_reader or compatibility_network
        super().__init__(
            inventory, mock, compatibility_network,
            RoutingEvidenceCollector(inventory, mock, compatibility_reader),
        )
        self.command_reader = compatibility_reader
