"""Explicit platform aliases and operation-level support."""
from dataclasses import dataclass
from types import MappingProxyType
import re

from ..domain.errors import UnsupportedCapability
from .cisco.ios import collector as ios
from .cisco.ios import health as ios_health
from .cisco.ios import routing as ios_routing
from .cisco.ios import bgp as ios_bgp
from .cisco import observations as cisco_observations
from .fortinet.fortios import collector as fortios
from .fortinet.fortios import health as fortios_health
from .fortinet.fortios import observations as fortinet_observations
from .fortinet.fortios import vpn as fortinet_vpn
from .fortinet.fortios import bgp as fortinet_bgp
from .aruba.aoscx import collector as aoscx
from .aruba.aosswitch import collector as aosswitch


@dataclass(frozen=True)
class Platform:
    name: str
    driver: str
    capabilities: frozenset[str]
    collector: object | None = None
    observation_collector: object | None = None
    health_collector: object | None = None
    routing_collector: object | None = None
    vpn_collector: object | None = None
    configuration_commands: object | None = None
    mock_configurations: object | None = None
    configuration_errors: object | None = None
    ospf_status_commands: object | None = None
    mock_ospf_status: object | None = None
    ospf_status_parser: object | None = None
    bgp_status_commands: object | None = None
    mock_bgp_status: object | None = None
    bgp_status_parser: object | None = None
    bgp_configuration_command: str | None = None
    mock_bgp_configuration: str | None = None
    bgp_routes_command: str | None = None
    mock_bgp_routes: str | None = None


@dataclass(frozen=True)
class ObservationAdapter:
    family: str
    netmiko_type: str
    commands: object
    collector: object


INSPECTION = frozenset({"inspection", "facts", "interfaces", "health", "ospf", "bgp", "configuration"})
PLATFORMS = {
    "cisco_ios": Platform(
        "cisco_ios", "cisco_ios", INSPECTION | {"mac", "topology", "ospf_trace"},
        collector=ios, observation_collector=cisco_observations,
        health_collector=ios_health, routing_collector=ios_routing,
        configuration_commands=MappingProxyType({
            "running": "show running-config", "startup": "show startup-config",
        }),
        mock_configurations=MappingProxyType({"running": ios.MOCK_CONFIG, "startup": ios.MOCK_CONFIG}),
        configuration_errors=MappingProxyType({}),
        ospf_status_commands=ios_routing.STATUS_COMMANDS,
        mock_ospf_status=MappingProxyType({
            "process": ios_routing.MOCK_STATUS["process"],
            "neighbors": ios_health.MOCK_OUTPUTS["ospf_neighbors"],
        }),
        ospf_status_parser=ios_routing.parse_status,
        bgp_status_commands=ios_bgp.COMMANDS,
        mock_bgp_status=ios_bgp.MOCK_OUTPUTS,
        bgp_status_parser=ios_bgp.parse_status,
        bgp_configuration_command="show running-config | section ^router bgp",
        mock_bgp_configuration=(
            "router bgp 65001\n bgp router-id 1.1.1.1\n"
            " neighbor 2.2.2.2 remote-as 65002\n neighbor 2.2.2.2 update-source Loopback0"
        ),
        bgp_routes_command="show ip bgp",
        mock_bgp_routes=(
            "     Network          Next Hop            Metric LocPrf Weight Path\n"
            " *>  10.20.0.0/24     2.2.2.2                  0    100      0 i"
        ),
    ),
    "cisco_nxos": Platform("cisco_nxos", "cisco_nxos", frozenset({"mac", "topology"}), None, cisco_observations),
    "fortinet": Platform(
        "fortinet", "fortinet", INSPECTION | {"mac", "vpn"}, collector=fortios,
        observation_collector=fortinet_observations, health_collector=fortios_health,
        vpn_collector=fortinet_vpn,
        configuration_commands=MappingProxyType({"running": "show"}),
        mock_configurations=MappingProxyType({"running": fortios.MOCK_CONFIG}),
        configuration_errors=MappingProxyType({
            "startup": "FortiOS does not provide a separate startup configuration; use running.",
        }),
        ospf_status_commands=fortios.OSPF_STATUS_COMMANDS,
        mock_ospf_status=MappingProxyType({
            "process": fortios.MOCK_OSPF_STATUS["process"],
            "neighbors": fortios_health.MOCK_OUTPUTS["ospf_neighbors"],
        }),
        ospf_status_parser=fortios.parse_ospf_status,
        bgp_status_commands=fortinet_bgp.COMMANDS,
        mock_bgp_status=fortinet_bgp.MOCK_OUTPUTS,
        bgp_status_parser=fortinet_bgp.parse_status,
        bgp_configuration_command="show router bgp",
        mock_bgp_configuration=(
            "config router bgp\n set as 65100\n set router-id 10.0.0.1\n"
            " config neighbor\n  edit 10.0.0.2\n   set remote-as 65200\n  next\n end\nend"
        ),
        bgp_routes_command="get router info bgp network",
        mock_bgp_routes=(
            "BGP table version is 1, local router ID is 10.0.0.1\n"
            "*> 10.20.0.0/24 10.0.0.2 0 100 0 65200 i"
        ),
    ),
    "aruba_aoscx": Platform("aruba_aoscx", "aruba_aoscx", frozenset({"mac", "topology"}), None, aoscx),
    "aruba_osswitch": Platform("aruba_osswitch", "aruba_osswitch", frozenset({"mac", "topology"}), None, aosswitch),
}


def _key(value):
    return re.sub(r"[\s_/-]", "", value.casefold())


ALIASES = {
    "cisco": {"": "cisco_ios", "ios": "cisco_ios", "iosxe": "cisco_ios",
              "iosiosxe": "cisco_ios", "ciscoios": "cisco_ios", "ciscoiosxe": "cisco_ios",
              "nxos": "cisco_nxos", "cisconxos": "cisco_nxos"},
    "fortinet": {"": "fortinet", "fortios": "fortinet", "fortinet": "fortinet"},
    "aruba": {"": "aruba_osswitch", "aoscx": "aruba_aoscx", "arubaaoscx": "aruba_aoscx",
              "aosswitch": "aruba_osswitch", "arubaosswitch": "aruba_osswitch", "procurve": "aruba_osswitch"},
}


def platform_for(device):
    vendor = _key(device.vendor)
    vendor = {"fortigate": "fortinet", "hpe": "aruba", "hewlettpackardenterprise": "aruba"}.get(vendor, vendor)
    name = ALIASES.get(vendor, {}).get(_key(device.platform))
    return PLATFORMS.get(name)


def supports(device, operation):
    platform = platform_for(device)
    return platform is not None and operation in platform.capabilities


def require(device, operation):
    platform = platform_for(device)
    if platform is None or operation not in platform.capabilities:
        raise UnsupportedCapability(
            "Device inspection supports Cisco IOS/IOS-XE and Fortinet FortiOS inventory records."
        )
    return platform


def observation_adapter_for(device):
    platform = platform_for(device)
    if platform is None or "mac" not in platform.capabilities:
        return None
    collector = platform.observation_collector
    return ObservationAdapter(
        platform.name, platform.driver, collector.COMMANDS, collector
    )


class CapabilityRegistry:
    """Injected application boundary over the static vendor registry."""

    platform_for = staticmethod(platform_for)
    require = staticmethod(require)
    supports = staticmethod(supports)
    observation_adapter_for = staticmethod(observation_adapter_for)


CAPABILITIES = CapabilityRegistry()
