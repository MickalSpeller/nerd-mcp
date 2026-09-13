"""Structured observations independent of transport and interface libraries."""
from dataclasses import dataclass, field
from typing import Generic, Literal, TypeVar


@dataclass(frozen=True)
class DeviceFacts:
    device_hostname: str | None = None
    serial_number: str | None = None
    model: str | None = None
    location: str | None = None


@dataclass(frozen=True)
class Interface:
    name: str
    address: str | None
    status: str | None
    protocol: str | None = None
    # None means unknown; True distinguishes an explicitly unassigned address.
    unassigned: bool | None = None


@dataclass(frozen=True)
class OspfProcess:
    process_id: str
    router_id: str


@dataclass(frozen=True)
class OspfNeighbor:
    neighbor_id: str
    state: str
    address: str
    interface: str


@dataclass(frozen=True)
class OspfStatus:
    running: bool | None
    processes: tuple[OspfProcess, ...]
    neighbors: tuple[OspfNeighbor, ...]
    complete: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class BgpNeighbor:
    neighbor: str
    remote_as: int | None
    state: str
    established: bool | None
    up_down: str
    prefixes_received: int | None = None


@dataclass(frozen=True)
class BgpStatus:
    router_id: str | None
    local_as: int | None
    running: bool | None
    neighbors: tuple[BgpNeighbor, ...]
    complete: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class VpnTunnel:
    name: str
    status: Literal["up", "down", "unknown"]
    remote_gateway: str | None = None
    selectors_total: int | None = None
    selectors_up: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None


@dataclass(frozen=True)
class VpnStatus:
    has_active_vpn: bool | None
    ipsec_tunnels: tuple[VpnTunnel, ...]
    ipsec_complete: bool
    ssl_vpn_session_count: int | None
    ssl_vpn_complete: bool
    complete: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfigurationSnapshot:
    source: str
    output: str
    revision: str | None
    total_chars: int
    total_lines: int
    redactions: int


@dataclass(frozen=True)
class RouteNextHop:
    address: str
    interface: str
    route_source_router_id: str | None = None


@dataclass(frozen=True)
class RouteDetail:
    found: bool
    prefix: str
    protocol: str
    distance: int | None
    metric: int | None
    route_type: str
    next_hops: tuple[RouteNextHop, ...]
    route_source_router_ids: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class OspfNeighborDetail:
    router_id: str
    address: str
    interface: str
    area: str
    state: str


@dataclass(frozen=True)
class OspfDatabaseEvidence:
    verified: bool
    advertising_router_ids: tuple[str, ...]
    link_state_ids: tuple[str, ...]


@dataclass(frozen=True)
class RouteEvidence:
    route: RouteDetail
    neighbors: tuple[OspfNeighborDetail, ...]
    commands: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    truncated: bool = False


@dataclass(frozen=True)
class OspfDatabaseCollection:
    lsa_type: str
    evidence: OspfDatabaseEvidence
    command: str
    warnings: tuple[str, ...] = ()
    truncated: bool = False


@dataclass(frozen=True)
class MacObservation:
    mac: str
    vlan: str
    interface: str
    entry_type: str
    role: str = "unknown"


@dataclass(frozen=True)
class ArpObservation:
    mac: str
    ip: str
    interface: str
    vrf: str = "default"


@dataclass(frozen=True)
class NeighborObservation:
    interface: str
    neighbor: str
    neighbor_address: str
    remote_interface: str
    protocol: str


@dataclass(frozen=True)
class InterfaceHealthObservation:
    interface: str
    status: str
    protocol: str
    description: str = ""
    input_errors: int = 0
    crc_errors: int = 0
    output_errors: int = 0
    speed: str = ""
    duplex: str = ""


@dataclass(frozen=True)
class ObservationBatch:
    macs: tuple[MacObservation, ...] = ()
    arps: tuple[ArpObservation, ...] = ()
    neighbors: tuple[NeighborObservation, ...] = ()
    interfaces: tuple[InterfaceHealthObservation, ...] = ()
    uplinks: frozenset[str] = frozenset()


HealthSeverity = Literal["critical", "warning", "ok", "info"]
HealthOverall = Literal["critical", "warning", "healthy", "unknown"]


@dataclass(frozen=True)
class HealthMetrics:
    interfaces_total: int | None = None
    interfaces_up: int | None = None
    interfaces_down: int | None = None
    interfaces_admin_down: int | None = None
    routes: int | None = None
    default_route: bool | None = None
    ospf_neighbors: int | None = None
    ospf_not_full: int | None = None
    bgp_neighbors: int | None = None
    bgp_not_established: int | None = None
    cpu_five_minute_percent: int | None = None
    memory_free_percent: float | None = None
    uptime: str | None = None


@dataclass(frozen=True)
class HealthFinding:
    id: str
    category: str
    severity: HealthSeverity
    summary: str
    complete: bool = True


@dataclass(frozen=True)
class HealthAssessment:
    overall: HealthOverall
    complete: bool
    counts: dict[HealthSeverity, int]
    metrics: HealthMetrics
    metric_fields: tuple[str, ...]
    checks: tuple[HealthFinding, ...]


T = TypeVar("T")


@dataclass
class CollectionResult(Generic[T]):
    device: str
    operation: str
    timestamp: str
    source: Literal["live", "mock", "cache"]
    schema_version: int = 1
    status: Literal["success", "partial", "unsupported", "error"] = "error"
    data: T | None = None
    complete: bool = False
    commands: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    error_code: str | None = None
    error: str | None = None
    # Sanitized, bounded text retained only for the legacy inspection serializer.
    raw_output: str = field(default="", repr=False)
    truncated: bool = False
