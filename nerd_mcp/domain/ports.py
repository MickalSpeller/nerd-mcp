"""Application-facing dependency contracts.

The protocols keep application and domain code independent from SQLite,
Netmiko, MCP, and terminal adapters.  Concrete implementations are selected in
``nerd_mcp.bootstrap``.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .inventory import Device
from .models import (
    BgpStatus,
    CollectionResult,
    ConfigurationSnapshot,
    DeviceFacts,
    Interface,
    OspfDatabaseCollection,
    OspfStatus,
    RouteEvidence,
    VpnStatus,
)


@runtime_checkable
class CapabilityProviderPort(Protocol):
    """Resolve platform capabilities without coupling workflows to vendor modules."""

    def platform_for(self, device: Device) -> Any | None: ...

    def require(self, device: Device, operation: str) -> Any: ...

    def supports(self, device: Device, operation: str) -> bool: ...

    def observation_adapter_for(self, device: Device) -> Any | None: ...


@runtime_checkable
class InventoryReader(Protocol):
    def list(self) -> list[Device]: ...

    def get(self, name: str) -> Device: ...

    def search(self, **filters: str) -> list[Device]: ...


@runtime_checkable
class InventoryPort(InventoryReader, Protocol):
    path: Path

    def connect(self) -> AbstractContextManager[Any]: ...

    def update_facts(self, name: str, facts: Mapping[str, str]) -> Device: ...

    def import_file(self, path: str | Path, update: bool = False) -> dict[str, int]: ...

    def remove(self, name: str) -> bool: ...


@runtime_checkable
class NetworkPort(Protocol):
    def collect_facts(self, name: str) -> CollectionResult[DeviceFacts]: ...

    def discover_inventory(self, name: str) -> dict[str, Any]: ...

    def collect_interfaces(self, name: str) -> CollectionResult[tuple[Interface, ...]]: ...

    def health(self, name: str) -> dict[str, Any]: ...

    def collect_ospf_status(self, name: str) -> CollectionResult[OspfStatus]: ...

    def ospf_status(self, name: str) -> dict[str, Any]: ...

    def collect_bgp_status(self, name: str) -> CollectionResult[BgpStatus]: ...

    def bgp_status(self, name: str) -> dict[str, Any]: ...

    def bgp_configuration(self, name: str) -> dict[str, Any]: ...

    def bgp_routes(self, name: str) -> dict[str, Any]: ...

    def collect_vpn_status(self, name: str) -> CollectionResult[VpnStatus]: ...

    def vpn_status(self, name: str) -> dict[str, Any]: ...

    def collect_configuration(
        self, name: str, source: str = "running"
    ) -> CollectionResult[ConfigurationSnapshot]: ...

    def configuration(self, name: str, source: str = "running") -> dict[str, Any]: ...

    def get_configuration(
        self, name: str, source: str, cursor: int, revision: str
    ) -> dict[str, Any]: ...


@runtime_checkable
class CommandCollectionPort(Protocol):
    """Collect fixed command sets selected by an application workflow."""

    def read_many(
        self, name: str, commands: Mapping[str, str], read_timeout: int,
        mock_outputs: Mapping[str, str], device_type: str | None = None,
    ) -> tuple[dict[str, str], str | None]: ...

    def read(
        self, name: str, command: str, read_timeout: int, mock_output: str,
    ) -> tuple[str, str | None]: ...


@runtime_checkable
class InspectionWorkflowPort(NetworkPort, CommandCollectionPort, Protocol):
    def inspect(self, operation: str, name: str) -> dict[str, Any]: ...


@runtime_checkable
class MacObservationPort(Protocol):
    def scan(self, target: str, workers: int = 4) -> dict[str, Any]: ...

    def scan_neighbors(self, target: str, workers: int = 4) -> dict[str, Any]: ...

    def locate(self, mac: str, max_age_minutes: int = 15) -> dict[str, Any]: ...

    def locate_ip(self, ip_address: str, max_age_minutes: int = 15) -> dict[str, Any]: ...

    def troubleshoot(self, mac: str, max_age_minutes: int = 15) -> dict[str, Any]: ...

    def interface_macs(
        self, device: str, interface: str, max_age_minutes: int = 15
    ) -> dict[str, Any]: ...

    def device_macs(
        self, device: str, max_age_minutes: int = 15
    ) -> dict[str, Any]: ...

    def device_arps(
        self, device: str, max_age_minutes: int = 15
    ) -> dict[str, Any]: ...


@runtime_checkable
class RouteTracingPort(Protocol):
    def trace(
        self, device: str, destination: str, workers: int = 4
    ) -> dict[str, Any]: ...


@runtime_checkable
class RoutingEvidencePort(Protocol):
    def collect_route(self, name: str, destination: str) -> RouteEvidence: ...

    def collect_database(
        self, name: str, lsa_type: str, key: str
    ) -> OspfDatabaseCollection: ...


@runtime_checkable
class TopologyWorkflowPort(Protocol):
    def get(
        self, target: str = "all", max_age_minutes: int = 60
    ) -> dict[str, Any]: ...

    def diagram_data(
        self, target: str = "all", location: str = "",
        max_age_minutes: int = 60,
    ) -> dict[str, Any]: ...

    def discover(
        self, target: str = "all", workers: int = 4,
        max_age_minutes: int = 60,
    ) -> dict[str, Any]: ...


@runtime_checkable
class TopologyDiagramPresenterPort(Protocol):
    def present(
        self, topology: Mapping[str, Any], output_format: str
    ) -> dict[str, Any]: ...


@runtime_checkable
class TopologyPort(Protocol):
    def get(
        self, target: str = "all", max_age_minutes: int = 60
    ) -> dict[str, Any]: ...

    def diagram(
        self, target: str = "all", location: str = "",
        max_age_minutes: int = 60, output_format: str = "text",
    ) -> dict[str, Any]: ...

    def discover(
        self, target: str = "all", workers: int = 4,
        max_age_minutes: int = 60,
    ) -> dict[str, Any]: ...


@runtime_checkable
class MacPathPort(Protocol):
    def trace(
        self, mac_address: str, source_device: str = "",
        max_age_minutes: int = 15, refresh: bool = False, workers: int = 4,
    ) -> dict[str, Any]: ...


@runtime_checkable
class EndpointResolutionPort(Protocol):
    def locate(
        self, identifier: str, source_device: str = "",
        max_age_minutes: int = 15, refresh: bool = False, workers: int = 4,
    ) -> dict[str, Any]: ...


@runtime_checkable
class DeviceTransportPort(Protocol):
    def connection(
        self, device: Device, device_type: str, read_timeout: int = 60
    ) -> AbstractContextManager[tuple[Any, str]]: ...

    def read_many(
        self,
        device: Device,
        device_type: str,
        commands: Mapping[str, str],
        read_timeout: int,
        *,
        retry_pooled_timeout: bool = False,
    ) -> tuple[dict[str, str], str | None]: ...


@runtime_checkable
class DeviceSessionFactoryPort(Protocol):
    def resolve_credentials(self, profile: str) -> tuple[str, str, str]: ...

    def connect(
        self, device: Device, device_type: str, username: str,
        password: str, read_timeout: int,
    ) -> Any: ...


@runtime_checkable
class ChangePlanningPort(Protocol):
    def plan(self, request) -> dict[str, Any]: ...


@runtime_checkable
class ChangeQueryPort(Protocol):
    def get(self, change_id: str) -> dict[str, Any]: ...
    def history(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class ChangeWritePort(Protocol):
    def authorize(self, change_id: str, action: str): ...
    def apply(self, change_id: str, *, authorization) -> dict[str, Any]: ...
    def save(self, change_id: str, *, authorization) -> dict[str, Any]: ...


@runtime_checkable
class ConnectionPoolPort(Protocol):
    def connection(
        self, device: Device, device_type: str, read_timeout: int = 60
    ) -> AbstractContextManager[tuple[Any, str]]: ...

    def close_all(self) -> None: ...


@runtime_checkable
class ObservationRepositoryPort(Protocol):
    def connect(self) -> AbstractContextManager[Any]: ...

    def prepare(self) -> None: ...

    def record_failure(self, device: str, timestamp: str, status: str, error: str) -> None: ...

    def record_topology_failure(
        self, device: str, timestamp: str, status: str, error: str
    ) -> None: ...

    def replace_neighbors(self, device: str, timestamp: str, status: str,
                          error: str | None, neighbors: list[dict],
                          mock: bool = False) -> None: ...

    def replace(self, device: str, timestamp: str, status: str,
                error: str | None, **observations: Any) -> None: ...

    def topology_snapshot(
        self,
    ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]: ...

    def mac_lookup_rows(self, mac: str) -> dict[str, Any]: ...

    def arp_lookup_rows(self, ip_address: str) -> dict[str, Any]: ...

    def interface_lookup_rows(self, device: str) -> dict[str, Any]: ...

    def device_mac_rows(self, device: str) -> dict[str, Any]: ...

    def device_arp_rows(self, device: str) -> dict[str, Any]: ...

@runtime_checkable
class BaselineRepositoryPort(Protocol):
    def connect(self) -> AbstractContextManager[Any]: ...

    def get(self, device: str) -> Any: ...

    def list(self) -> list[Any]: ...

    def captured_at(self, device: str) -> Any: ...

    def save(self, values: tuple, replace: bool) -> None: ...

    def remove(self, device: str) -> bool: ...

    def record_comparison(self, summary: dict[str, Any], checked_at: str) -> None: ...

    def status_rows(self) -> list[Any]: ...
