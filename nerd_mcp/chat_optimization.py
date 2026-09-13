"""Deterministic planning and bounded model context for the NERD chat client."""

from __future__ import annotations

import re
from dataclasses import dataclass


MAX_AGENT_CALLS = 32
RECENT_TURNS = 6
MEMORY_CHARS = 4000

INVENTORY_TOOLS = {
    "list_devices", "get_inventory_device", "search_devices", "get_device_facts",
}
BASIC_TOOLS = {
    "list_devices", "get_inventory_device", "get_device_info", "get_device_facts",
    "get_interfaces", "get_vlans", "get_routes", "get_neighbors",
}
HEALTH_TOOLS = BASIC_TOOLS | {
    "get_health", "get_ospf_status", "get_bgp_status", "get_bgp_configuration",
    "get_bgp_routes",
}
VPN_TOOLS = INVENTORY_TOOLS | {"get_vpn_status"}
ROUTING_TOOLS = HEALTH_TOOLS | {"trace_ospf_route"}
MAC_TOOLS = INVENTORY_TOOLS | {
    "refresh_mac_observations", "locate_mac", "troubleshoot_mac", "get_device_macs",
    "get_device_arps", "get_interface_macs",
    "locate_endpoint", "trace_mac_path", "get_topology", "discover_topology",
}
TOPOLOGY_TOOLS = INVENTORY_TOOLS | {
    "get_neighbors", "discover_topology", "get_topology", "get_topology_diagram",
}
CONFIG_TOOLS = INVENTORY_TOOLS | {
    "get_configuration", "list_configuration_baselines", "get_configuration_baseline",
    "compare_configuration_baseline", "compare_all_configuration_baselines",
    "get_configuration_baseline_status",
}

IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
MAC = re.compile(
    r"(?i)(?<![0-9a-f])(?:(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|"
    r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{6}-[0-9a-f]{6})(?![0-9a-f])"
)
DEVICE_AFTER = re.compile(
    r"(?i)\b(?:on|in|for|from|of|about)\s+([a-z0-9][a-z0-9_.-]*)\b"
)


@dataclass(frozen=True)
class ChatPlan:
    mode: str = "agent"  # local, prefetch, or agent
    tool: str | None = None
    arguments: dict[str, object] | None = None
    tool_names: frozenset[str] | None = None
    max_calls: int = 8
    reasoning: str = "low"
    verbosity: str = "medium"
    max_output_tokens: int = 2000
    stream: bool = False
    label: str = "Agent fallback"
    local_filter: dict[str, str] | None = None
    prefetch_steps: tuple[tuple[str, dict[str, object]], ...] = ()


def _device(question: str) -> str | None:
    match = DEVICE_AFTER.search(question)
    if match:
        candidate = match.group(1).rstrip("?.!,")
        if candidate.casefold() not in {
            "the", "a", "an", "all", "current", "device", "is", "are", "was", "were",
        }:
            return candidate
    # Common short inventory names such as R1, SW2, FW-01.
    tokens = re.findall(r"\b[A-Za-z]{1,8}[A-Za-z-]*\d+[A-Za-z0-9_.-]*\b", question)
    return tokens[-1] if tokens else None


def _devices(question: str) -> tuple[str, ...]:
    """Return unique explicit short inventory-style names in mention order."""
    result = []
    for token in re.findall(r"\b[A-Za-z]{1,8}[A-Za-z-]*\d+[A-Za-z0-9_.-]*\b", question):
        if token.casefold() not in {item.casefold() for item in result}:
            result.append(token)
    return tuple(result)


def _agent_scope(question: str) -> tuple[frozenset[str] | None, int, str, str, int]:
    text = question.casefold()
    if any(word in text for word in ("configuration", "running-config", "startup-config",
                                      "baseline", "snapshot", "config drift")):
        return frozenset(CONFIG_TOOLS), MAX_AGENT_CALLS, "medium", "high", 4000
    if any(word in text for word in ("topology", "neighbor", "connected to", "link")):
        return frozenset(TOPOLOGY_TOOLS), 10, "low", "medium", 2500
    if MAC.search(question) or any(word in text for word in ("mac address", "endpoint", "arp")):
        return frozenset(MAC_TOOLS), 10, "low", "medium", 2500
    if any(word in text for word in ("vpn", "ipsec", "ssl-vpn", "ssl vpn")):
        return frozenset(VPN_TOOLS), 4, "low", "medium", 2000
    if any(word in text for word in ("ospf", "bgp", "route", "routing", "next hop", "advertis")):
        return frozenset(ROUTING_TOOLS), 10, "medium", "medium", 2500
    if any(word in text for word in ("health", "errors", "cpu", "memory", "uptime")):
        return frozenset(HEALTH_TOOLS), 6, "low", "medium", 2500
    if any(word in text for word in ("inventory", "serial", "model", "location", "hostname")):
        return frozenset(INVENTORY_TOOLS), 6, "low", "medium", 2000
    return None, 8, "low", "medium", 2000


def plan_question(question: str, available_tools: set[str]) -> ChatPlan:
    """Choose only high-confidence shortcuts; uncertain questions retain the full agent."""
    text = " ".join(question.casefold().split())
    device = _device(question)
    devices = _devices(question)

    if "list_devices" in available_tools and (
        re.fullmatch(r"(?:please )?(?:list|show)(?: me)?(?: all| the| my)? devices(?: in (?:the )?inventory)?[?.!]?", text)
        or text in {"what devices do i have", "what devices do i have?"}
    ):
        return ChatPlan(mode="local", tool="list_devices", arguments={}, max_calls=0,
                        reasoning="none", verbosity="low", max_output_tokens=0,
                        label="Local fast path")

    location_match = re.fullmatch(
        r"(?i)(?:what|which|show|list)(?: me)?(?: all)?\s+"
        r"(?:(firewalls?|routers?|switches?|devices?)\s+)?"
        r"(?:(?:is|are)\s+)?located\s+(?:in|at)\s+(.+?)[?.!]?", question.strip()
    )
    if "list_devices" in available_tools and location_match:
        kind = (location_match.group(1) or "").casefold().rstrip("s")
        if kind == "device":
            kind = ""
        place = location_match.group(2).strip().rstrip("?.!")
        return ChatPlan(
            mode="local", tool="list_devices", arguments={}, max_calls=0,
            reasoning="none", verbosity="low", max_output_tokens=0,
            label="Local fast path",
            local_filter={"device_type": kind, "place": place},
        )

    if device and "get_inventory_device" in available_tools and re.search(
        r"(?i)\b(?:inventory record|stored inventory|local record)\b", question
    ):
        return ChatPlan(mode="local", tool="get_inventory_device",
                        arguments={"device": device}, max_calls=0, reasoning="none",
                        verbosity="low", max_output_tokens=0, label="Local fast path")

    tool = None
    arguments: dict[str, object] | None = None
    steps: tuple[tuple[str, dict[str, object]], ...] = ()
    interface_match = re.search(
        r"(?i)\b(?:port|interface)\s+([a-z][a-z0-9.-]*(?:/\d+)+(?:\.\d+)?)\b", question
    )
    if (device and "refresh_mac_observations" in available_tools
            and "get_device_arps" in available_tools and re.search(
                r"(?i)\b(?:show|list|display|retrieve|what(?:'s| is)?)\b.*"
                r"\b(?:arp table|arp entries|arp cache)\b", question
            )):
        tool = "get_device_arps"
        arguments = {"device": device, "max_age_minutes": 15}
        steps = (
            ("refresh_mac_observations", {"target": device, "workers": 4}),
            (tool, arguments),
        )
    elif (device and "refresh_mac_observations" in available_tools
            and "get_device_macs" in available_tools and re.search(
                r"(?i)\b(?:show|list|display|retrieve|what(?:'s| is)?)\b.*"
                r"\b(?:mac address table|mac table|all mac addresses)\b", question
            )):
        tool = "get_device_macs"
        arguments = {"device": device, "max_age_minutes": 15}
        steps = (
            ("refresh_mac_observations", {"target": device, "workers": 4}),
            (tool, arguments),
        )
    elif (device and interface_match and "refresh_mac_observations" in available_tools
            and "get_interface_macs" in available_tools and re.search(
                r"(?i)\bmac(?: address(?:es)?)?\b", question
            )):
        tool = "get_interface_macs"
        arguments = {"device": device, "interface": interface_match.group(1),
                     "max_age_minutes": 15}
        steps = (
            ("refresh_mac_observations", {"target": device, "workers": 4}),
            (tool, arguments),
        )
    elif device and "get_device_facts" in available_tools and re.search(
        r"(?i)\b(?:serial number|(?:device\s+)?hostname|(?:device|chassis)\s+model|"
        r"model\s+of|(?:device-reported\s+)?location)\b", question
    ):
        tool, arguments = "get_device_facts", {"device": device}
        inventory_step = (("get_inventory_device", {"device": device}),) \
            if "get_inventory_device" in available_tools else ()
        steps = (*inventory_step, (tool, arguments))
    elif device and "get_vpn_status" in available_tools and re.search(
        r"(?i)\b(?:vpn|ipsec|ssl[ -]?vpn)\b.*\b(?:tunnels?|sessions?|status|active|up|down)\b|"
        r"\b(?:has?|have|show|list|check|does)\b.*\b(?:vpn|ipsec|ssl[ -]?vpn)\b",
        question,
    ):
        tool, arguments = "get_vpn_status", {"device": device}
    elif device and "get_ospf_status" in available_tools and re.search(
        r"(?i)\bospf\b.*\b(?:running|enabled|active|neighbors?|adjacen)|"
        r"\b(?:running|enabled|active)\b.*\bospf\b", question
    ):
        tool, arguments = "get_ospf_status", {"device": device}
    elif (len(devices) >= 2
            and {"get_bgp_status", "get_bgp_configuration"} <= available_tools
            and re.search(r"(?i)\bbgp\b", question)
            and re.search(r"(?i)\b(?:problem|wrong|fail|down|idle|active|troubleshoot|fix|correct|suggest|recommend|peer)", question)):
        selected = devices[:2]
        tool, arguments = "get_bgp_status", {"device": selected[0]}
        steps = tuple(
            (name, {"device": target})
            for target in selected
            for name in ("get_bgp_status", "get_bgp_configuration")
        )
    elif device and "get_bgp_routes" in available_tools and re.search(
        r"(?i)\bbgp\b.*\b(?:routes?|routing table|prefixes?|networks?|paths?)\b|"
        r"\b(?:show|list|what|which)\b.*\bbgp\b.*\b(?:routes?|prefixes?|networks?)\b",
        question,
    ):
        tool, arguments = "get_bgp_routes", {"device": device}
    elif device and "get_bgp_status" in available_tools and re.search(
        r"(?i)\bbgp\b.*\b(?:summary|status|session|peer|neighbor|established|up|down|duration|how long)|"
        r"\b(?:how long|status|up|down|established)\b.*\bbgp\b", question
    ):
        tool, arguments = "get_bgp_status", {"device": device}
    elif device and "get_interfaces" in available_tools and re.search(
        r"(?i)\b(?:show|list|check|inspect|what|status)\b.*\binterfaces?\b", question
    ):
        tool, arguments = "get_interfaces", {"device": device}
    elif device and "get_health" in available_tools and re.search(
        r"(?i)\b(?:health|healthy|health check)\b", question
    ):
        tool, arguments = "get_health", {"device": device}
    elif device and "get_device_info" in available_tools and re.search(
        r"(?i)\b(?:device information|device info|version|uptime|tell me about)\b", question
    ):
        tool, arguments = "get_device_info", {"device": device}
    elif "trace_ospf_route" in available_tools and device and IPV4.search(question) and re.search(
        r"(?i)\b(?:ospf|route|next[ -]?hop|advertis|originat|reach)\w*\b", question
    ):
        tool, arguments = "trace_ospf_route", {
            "device": device, "destination": IPV4.search(question).group(0), "workers": 4,
        }
    elif "locate_endpoint" in available_tools and (IPV4.search(question) or MAC.search(question)) and re.search(
        r"(?i)\b(?:where|locate|find|connected|attached|endpoint)\b", question
    ):
        identifier = (MAC.search(question) or IPV4.search(question)).group(0)
        tool, arguments = "locate_endpoint", {
            "identifier": identifier, "source_device": device or "",
            "max_age_minutes": 15, "refresh": True, "workers": 4,
        }
    elif "trace_mac_path" in available_tools and MAC.search(question) and re.search(
        r"(?i)\b(?:path|trace|through|travers)\w*\b", question
    ):
        tool, arguments = "trace_mac_path", {
            "mac_address": MAC.search(question).group(0), "source_device": device or "",
            "max_age_minutes": 15, "refresh": True, "workers": 4,
        }
    elif "discover_topology" in available_tools and re.search(
        r"(?i)\b(?:current topology|discover topology|what is connected|neighbors?)\b", question
    ) and not re.search(r"(?i)\b(?:cached|stored|last known|offline)\b", question):
        tool, arguments = "discover_topology", {
            "target": device or "all", "workers": 4, "max_age_minutes": 60,
        }

    if tool:
        if not steps:
            steps = ((tool, arguments or {}),)
        analysis = bool(re.search(
            r"(?i)\b(?:why|analy[sz]e|troubleshoot|recommend|suggest|compare|problem|wrong|fix)\b",
            question,
        ))
        return ChatPlan(
            mode="prefetch", tool=tool, arguments=arguments,
            tool_names=frozenset(), max_calls=1,
            reasoning="medium" if analysis else "low",
            verbosity="high" if analysis else "medium",
            max_output_tokens=3000 if analysis else 2000,
            stream=(not analysis and tool == "get_device_facts"),
            label="Prefetch + one OpenAI call",
            prefetch_steps=steps,
        )

    scope, calls, reasoning, verbosity, tokens = _agent_scope(question)
    return ChatPlan(tool_names=scope, max_calls=calls, reasoning=reasoning,
                    verbosity=verbosity, max_output_tokens=tokens)


def render_local_result(tool: str, output: dict[str, object], local_filter=None) -> str:
    """Render the deliberately small set of zero-model answers."""
    if output.get("status") == "error":
        return f"Unable to retrieve the local inventory data: {output.get('error', 'unknown error')}"
    result = output.get("result")
    if not isinstance(result, dict):
        return "The local inventory returned no structured data."
    if tool == "list_devices":
        devices = result.get("devices") or []
        if local_filter:
            kind = local_filter.get("device_type", "").casefold()
            place = local_filter.get("place", "").casefold()
            filtered = []
            for row in devices:
                if not isinstance(row, dict):
                    continue
                row_kind = str(row.get("device_type") or "").casefold()
                places = " ".join(str(row.get(key) or "") for key in (
                    "location", "street_address", "city", "state", "zipcode", "country"
                )).casefold()
                if kind and row_kind != kind:
                    continue
                if place and place not in places:
                    continue
                filtered.append(row)
            devices = filtered
        if not devices:
            return ("No inventory devices matched that location query." if local_filter else
                    "No devices are currently recorded in the NERD inventory.")
        lines = ["## Device Inventory", "", "| Name | Host | Type | Location | Model | Serial |",
                 "|---|---|---|---|---|---|"]
        for row in devices:
            if not isinstance(row, dict):
                continue
            location = row.get("location") or ", ".join(
                str(row.get(key) or "") for key in ("city", "state") if row.get(key)
            )
            values = [row.get("name"), row.get("host"), row.get("device_type"), location,
                      row.get("model"), row.get("serial_number")]
            lines.append("| " + " | ".join(str(value or "—").replace("|", "\\|") for value in values) + " |")
        lines.extend(["", f"**Devices:** {len(devices)}"])
        return "\n".join(lines)
    if tool == "get_inventory_device":
        row = result.get("device")
        if not isinstance(row, dict):
            return "The device is not present in the local inventory."
        labels = (("Name", "name"), ("Management host", "host"), ("Hostname", "device_hostname"),
                  ("Type", "device_type"), ("Location", "location"), ("City", "city"),
                  ("State", "state"), ("Country", "country"), ("Model", "model"),
                  ("Serial number", "serial_number"), ("Platform", "platform"))
        return "## Local Inventory Record\n\n" + "\n".join(
            f"- **{label}:** {row.get(key) or 'Not recorded'}" for label, key in labels
        )
    return "The local request completed successfully."
