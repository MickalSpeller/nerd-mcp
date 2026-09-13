"""Stable application facades over application-owned workflow implementations."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ..domain.ports import (
    EndpointResolutionPort,
    InspectionWorkflowPort,
    MacObservationPort,
    MacPathPort,
    RouteTracingPort,
    TopologyDiagramPresenterPort,
    TopologyWorkflowPort,
)


class NetworkInspectionService:
    """Expose device inspection and fixed-command collection to adapters."""

    def __init__(self, workflow: InspectionWorkflowPort):
        self._workflow = workflow

    def inspect(self, operation, name):
        return self._workflow.inspect(operation, name)

    def collect_facts(self, name):
        return self._workflow.collect_facts(name)

    def discover_inventory(self, name):
        return self._workflow.discover_inventory(name)

    def collect_interfaces(self, name):
        return self._workflow.collect_interfaces(name)

    def health(self, name):
        return self._workflow.health(name)

    def collect_ospf_status(self, name):
        return self._workflow.collect_ospf_status(name)

    def ospf_status(self, name):
        return self._workflow.ospf_status(name)

    def collect_bgp_status(self, name):
        return self._workflow.collect_bgp_status(name)

    def bgp_status(self, name):
        return self._workflow.bgp_status(name)

    def bgp_configuration(self, name):
        return self._workflow.bgp_configuration(name)

    def bgp_routes(self, name):
        return self._workflow.bgp_routes(name)

    def collect_vpn_status(self, name):
        return self._workflow.collect_vpn_status(name)

    def vpn_status(self, name):
        return self._workflow.vpn_status(name)

    def collect_configuration(self, name, source="running"):
        return self._workflow.collect_configuration(name, source)

    def configuration(self, name, source="running"):
        return self._workflow.configuration(name, source)

    def get_configuration(self, name, source, cursor, revision):
        return self._workflow.get_configuration(name, source, cursor, revision)

    def read_many(self, name: str, commands: Mapping[str, str], read_timeout: int,
                  mock_outputs: Mapping[str, str], device_type: str | None = None):
        return self._workflow.read_many(
            name, commands, read_timeout, mock_outputs, device_type
        )

    def read(self, name: str, command: str, read_timeout: int, mock_output: str):
        return self._workflow.read(name, command, read_timeout, mock_output)


class MacObservationService:
    """Expose MAC, ARP, interface, and neighbor observation workflows."""

    def __init__(self, workflow: MacObservationPort):
        self._workflow = workflow

    def scan(self, target, workers=4):
        return self._workflow.scan(target, workers)

    def scan_neighbors(self, target, workers=4):
        return self._workflow.scan_neighbors(target, workers)

    def locate(self, mac, max_age_minutes=15):
        return self._workflow.locate(mac, max_age_minutes)

    def locate_ip(self, ip_address, max_age_minutes=15):
        return self._workflow.locate_ip(ip_address, max_age_minutes)

    def troubleshoot(self, mac, max_age_minutes=15):
        return self._workflow.troubleshoot(mac, max_age_minutes)

    def interface_macs(self, device, interface, max_age_minutes=15):
        return self._workflow.interface_macs(device, interface, max_age_minutes)

    def device_macs(self, device, max_age_minutes=15):
        return self._workflow.device_macs(device, max_age_minutes)

    def device_arps(self, device, max_age_minutes=15):
        return self._workflow.device_arps(device, max_age_minutes)

    def locate_current(self, mac, max_age_minutes=15, workers=4,
                       force_refresh=False, on_collection=None):
        return self._query_with_freshness(
            lambda: self._workflow.locate(mac, max_age_minutes),
            "all", workers, force_refresh, on_collection,
        )

    def troubleshoot_current(self, mac, max_age_minutes=15, workers=4,
                             force_refresh=False, on_collection=None):
        return self._query_with_freshness(
            lambda: self._workflow.troubleshoot(mac, max_age_minutes),
            "all", workers, force_refresh, on_collection,
        )

    def interface_macs_current(self, device, interface, max_age_minutes=15,
                               workers=4, force_refresh=False,
                               on_collection=None):
        return self._query_with_freshness(
            lambda: self._workflow.interface_macs(
                device, interface, max_age_minutes
            ),
            device, workers, force_refresh, on_collection,
        )

    def device_macs_current(self, device, max_age_minutes=15, workers=1,
                            force_refresh=False, on_collection=None):
        return self._query_with_freshness(
            lambda: self._workflow.device_macs(device, max_age_minutes),
            device, workers, force_refresh, on_collection,
        )

    def device_arps_current(self, device, max_age_minutes=15, workers=1,
                            force_refresh=False, on_collection=None):
        return self._query_with_freshness(
            lambda: self._workflow.device_arps(device, max_age_minutes),
            device, workers, force_refresh, on_collection,
        )

    def _query_with_freshness(
            self, query: Callable[[], dict], target: str, workers: int,
            force_refresh: bool,
            on_collection: Callable[[str, str], None] | None) -> dict:
        result = query()
        reason = self._refresh_reason(result, force_refresh)
        collection = None
        if reason:
            if on_collection is not None:
                on_collection(reason, target)
            collection = self._workflow.scan(target, workers)
            result = query()
        result = dict(result)
        result.update({
            "refreshed": collection is not None,
            "refresh_reason": reason,
            "collection_counts": (
                None if collection is None else collection.get("counts")
            ),
        })
        return result

    @staticmethod
    def _refresh_reason(result: Mapping, force_refresh: bool) -> str | None:
        if force_refresh:
            return "forced"
        refreshable = {"not_scanned", "stale"}
        if (result.get("scan_status") in refreshable
                and not result.get("error")):
            return "missing_or_stale"
        if any(
            row.get("status") in refreshable and not row.get("error")
            for row in result.get("incomplete_devices", ())
        ):
            return "missing_or_stale"
        return None


class RouteTracingService:
    def __init__(self, workflow: RouteTracingPort):
        self._workflow = workflow

    def trace(self, device, destination, workers=4):
        return self._workflow.trace(device, destination, workers)


class TopologyApplicationService:
    def __init__(self, workflow: TopologyWorkflowPort,
                 presenter: TopologyDiagramPresenterPort):
        self._workflow = workflow
        self._presenter = presenter

    def get(self, target="all", max_age_minutes=60):
        return self._workflow.get(target, max_age_minutes)

    def diagram(self, target="all", location="", max_age_minutes=60,
                output_format="text"):
        return self._presenter.present(
            self._workflow.diagram_data(target, location, max_age_minutes),
            output_format,
        )

    def discover(self, target="all", workers=4, max_age_minutes=60):
        return self._workflow.discover(target, workers, max_age_minutes)


class MacPathApplicationService:
    def __init__(self, workflow: MacPathPort):
        self._workflow = workflow

    def trace(self, mac_address, source_device="", max_age_minutes=15,
              refresh=False, workers=4):
        return self._workflow.trace(
            mac_address, source_device, max_age_minutes, refresh, workers
        )


class EndpointResolutionService:
    def __init__(self, workflow: EndpointResolutionPort):
        self._workflow = workflow

    def locate(self, identifier, source_device="", max_age_minutes=15,
               refresh=False, workers=4):
        return self._workflow.locate(
            identifier, source_device, max_age_minutes, refresh, workers
        )
