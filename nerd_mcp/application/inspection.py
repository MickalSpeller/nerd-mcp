"""Application-owned fixed inspection workflow."""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping
from datetime import datetime, timezone

from ..domain.errors import InventoryError, UnsupportedCapability
from ..domain.models import (
    CollectionResult,
    BgpStatus,
    ConfigurationSnapshot,
    DeviceFacts,
    Interface,
    VpnStatus,
)
from ..domain.ports import (
    CapabilityProviderPort,
    DeviceTransportPort,
    InventoryReader,
)
from .serialization import (
    configuration_legacy,
    facts_legacy,
    health_legacy,
    interfaces_legacy,
    ospf_status_legacy,
    bgp_status_legacy,
    vpn_status_legacy,
)

MAX_OUTPUT = 16_000
CONFIG_PAGE_CHARS = 12_000
LOG = logging.getLogger("nerd_mcp.operations")

def _redacted_line(line: str) -> str:
    """Preserve indentation while hiding an entire secret-bearing command."""
    indent = line[: len(line) - len(line.lstrip())]
    return indent + "! [REDACTED secret-bearing command]"


def sanitize_configuration(output: str, ssh_password: str | None = None) -> tuple[str, int]:
    """Remove common IOS/IOS-XE secrets before configuration leaves this process."""
    redactions = 0
    sanitized: list[str] = []
    in_private_key = False
    secret_patterns = (
        r"^\s*enable\s+(?:secret|password)\b",
        r"^\s*username\s+\S+.*\s(?:secret|password)\b",
        r"^\s*snmp-server\s+(?:community|host|user)\b",
        r"^\s*(?:radius-server|tacacs-server)\s+key\b",
        r"^\s+key\s+\S+",
        r"^\s*key-string\b",
        r"^\s*(?:password|secret)\s+(?:\d+\s+)?\S+",
        r"^(?!\s*(?:no|service)\s)\s*.*\b(?:password|secret)\s+(?:\d+\s+)?\S+",
        r"^\s*ip\s+ospf\s+(?:authentication-key|message-digest-key)\b",
        r"^\s*.*\b(?:authentication-key|message-digest-key|hex-key)\b",
        r"^\s*ntp\s+authentication-key\b",
        r"^\s*neighbor\s+\S+\s+password\b",
        r"^\s*(?:standby|vrrp)\s+\S+\s+authentication\b",
        r"^\s*crypto\s+isakmp\s+key\b",
        r"^\s*pre-shared-key\b",
        r"^\s*ppp\s+(?:chap|pap)\s+password\b",
        r"^\s*tunnel\s+password\b",
        r"^\s*set\s+(?:password|passwd|secret|psksecret|private-key|auth-pwd|key)\b",
    )
    for original in output.splitlines():
        line = original
        if re.search(r"-----BEGIN .*PRIVATE KEY-----", line, re.IGNORECASE):
            in_private_key = True
            sanitized.append(line)
            continue
        if in_private_key:
            if re.search(r"-----END .*PRIVATE KEY-----", line, re.IGNORECASE):
                in_private_key = False
                sanitized.append(line)
            else:
                if not sanitized or "[REDACTED private key material]" not in sanitized[-1]:
                    sanitized.append("[REDACTED private key material]")
                redactions += 1
            continue
        password_replaced = bool(ssh_password and ssh_password in line)
        if password_replaced:
            line = line.replace(ssh_password, "[REDACTED]")
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in secret_patterns):
            sanitized.append(_redacted_line(line))
            redactions += 1
        else:
            sanitized.append(line)
            if password_replaced:
                redactions += 1
    return "\n".join(sanitized), redactions


class NetworkWorkflow:
    """Device inspection workflow with all infrastructure supplied by its caller."""

    def __init__(self, inventory: InventoryReader, mock: bool,
                 transport: DeviceTransportPort,
                 capability_provider: CapabilityProviderPort,
                 error_mapper, command_rejected,
                 max_output: int = MAX_OUTPUT,
                 config_page_chars: int = CONFIG_PAGE_CHARS):
        self.inventory = inventory
        self.mock = mock
        self.transport = transport
        self.capabilities = capability_provider
        self.error_mapper = error_mapper
        self.command_rejected = command_rejected
        self.max_output = max_output
        self.config_page_chars = config_page_chars

    def _read_many(self, name: str, commands: Mapping[str, str], read_timeout: int,
                   mock_outputs: Mapping[str, str], netmiko_type: str | None = None) -> tuple[dict[str, str], str | None]:
        device = self.inventory.get(name)
        device_family = netmiko_type or self.capabilities.require(device, "inspection").driver
        if self.mock:
            return {
                key: "[MOCK DATA - not a live device]\n" + mock_outputs[key]
                for key in commands
            }, None
        return self.transport.read_many(
            device, device_family, commands, read_timeout, retry_pooled_timeout=True
        )

    def _read(self, name: str, command: str, read_timeout: int, mock_output: str) -> tuple[str, str | None]:
        outputs, password = self._read_many(
            name, {"result": command}, read_timeout, {"result": mock_output}
        )
        return outputs["result"], password

    def read_many(self, name: str, commands: Mapping[str, str], read_timeout: int,
                  mock_outputs: Mapping[str, str],
                  device_type: str | None = None) -> tuple[dict[str, str], str | None]:
        """Public fixed-command collection boundary for application workflows."""
        return self._read_many(
            name, commands, read_timeout, mock_outputs, device_type
        )

    def read(self, name: str, command: str, read_timeout: int,
             mock_output: str) -> tuple[str, str | None]:
        """Public single-command collection boundary for application workflows."""
        return self._read(name, command, read_timeout, mock_output)

    def inspect(self, operation: str, name: str) -> dict:
        if operation == "get_interfaces":
            return interfaces_legacy(self.collect_interfaces(name))
        try:
            platform = self.capabilities.require(self.inventory.get(name), "inspection")
            family = platform.driver
        except Exception as exc:
            return {"device": name, "command": None, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "error", "output": "", "error": self.error_mapper(exc),
                    "truncated": False, "mock": self.mock}
        command_map = platform.collector.COMMANDS
        mock_map = platform.collector.MOCK_OUTPUTS
        command = command_map.get(operation)
        result = {"device": name, "command": command,
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "status": "error", "output": "", "error": None,
                  "truncated": False, "mock": self.mock}
        try:
            if command is None:
                raise InventoryError("Unsupported operation.")
            output, password = self._read_many(
                name, {"result": command}, 30, {"result": mock_map[operation]}, family
            )
            output = output["result"]
            if password:
                output = output.replace(password, "[REDACTED]")
            if self.command_rejected(output):
                result["error"] = "Command unsupported or not permitted by this device/account."
            else:
                result["status"] = "success"
            result["truncated"] = len(output) > self.max_output
            result["output"] = output[:self.max_output] + ("\n[OUTPUT TRUNCATED]" if result["truncated"] else "")
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
        LOG.info("operation=%s status=%s mock=%s", operation if command else "rejected", result["status"], self.mock)
        return result

    def collect_facts(self, name: str) -> CollectionResult[DeviceFacts]:
        """Return structured facts; unknown fields remain None."""
        result = CollectionResult(name, "facts", datetime.now(timezone.utc).isoformat(),
                                  "mock" if self.mock else "live")
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "facts")
            collector = platform.collector
            result.commands = tuple(collector.DISCOVERY_COMMANDS.values())
            outputs, password = self._read_many(
                name, collector.DISCOVERY_COMMANDS, 60, collector.MOCK_DISCOVERY, platform.driver
            )
            if password:
                outputs = {key: value.replace(password, "[REDACTED]") for key, value in outputs.items()}
            facts = collector.parse_facts(outputs)
            result.data = DeviceFacts(**{key: value or None for key, value in facts.items()})
            result.complete = all(facts.values()) and not any(self.command_rejected(text) for text in outputs.values())
            result.status = "success" if result.complete else "partial"
            if not result.complete:
                result.warnings = ("Some device facts are unknown or unavailable.",)
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = "unsupported_capability" if result.status == "unsupported" else "collection_failed"
            result.error = self.error_mapper(exc)
        return result

    def discover_inventory(self, name: str) -> dict:
        result = facts_legacy(self.collect_facts(name))
        LOG.info("operation=discover_inventory status=%s mock=%s", result["status"], self.mock)
        return result

    def collect_interfaces(self, name: str) -> CollectionResult[tuple[Interface, ...]]:
        """Collect structured interfaces with bounded compatibility text."""
        result = CollectionResult(name, "interfaces", datetime.now(timezone.utc).isoformat(),
                                  "mock" if self.mock else "live")
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "interfaces")
            collector = platform.collector
            command = collector.COMMANDS["get_interfaces"]
            result.commands = (command,)
            outputs, password = self._read_many(name, {"result": command}, 30,
                {"result": collector.MOCK_OUTPUTS["get_interfaces"]}, platform.driver)
            output = outputs["result"]
            if password:
                output = output.replace(password, "[REDACTED]")
            result.truncated = len(output) > self.max_output
            text = output[:self.max_output]
            result.raw_output = text + ("\n[OUTPUT TRUNCATED]" if result.truncated else "")
            if self.command_rejected(output):
                result.error = "Command unsupported or not permitted by this device/account."
                result.error_code = "command_rejected"
            else:
                # Never correlate a row cut in half by the compatibility limit.
                parsed_text = text.rsplit("\n", 1)[0] if result.truncated else text
                if result.truncated and "\n" not in text:
                    parsed_text = ""
                result.data, result.warnings = collector.parse_interfaces(parsed_text)
                if result.truncated:
                    result.warnings += ("Interface output was truncated before all addresses could be checked.",)
                result.complete = not result.warnings
                result.status = "success" if result.complete else "partial"
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = "unsupported_capability" if result.status == "unsupported" else "collection_failed"
            result.error = self.error_mapper(exc)
        if result.commands:
            LOG.info("operation=get_interfaces status=%s mock=%s",
                     "success" if result.status in {"success", "partial"} else "error", self.mock)
        return result

    def health(self, name: str) -> dict:
        """Run fixed read-only commands and return parsed operational findings."""
        result = {
            "device": name,
            "commands": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "error",
            "overall": "unknown",
            "complete": False,
            "counts": {"critical": 0, "warning": 0, "ok": 0, "info": 0},
            "metrics": {},
            "checks": [],
            "error": None,
            "mock": self.mock,
        }
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "health")
            family = platform.driver
            collector = platform.health_collector
            if collector is None:
                raise UnsupportedCapability("Health collection is not available for this platform.")
            commands = collector.COMMANDS
            mock_outputs = collector.MOCK_OUTPUTS
            result["commands"] = list(commands.values())
            outputs, password = self._read_many(name, commands, 60, mock_outputs, family)
            if password:
                outputs = {key: value.replace(password, "[REDACTED]") for key, value in outputs.items()}
            parsed = health_legacy(collector.parse_health(outputs, device.device_type))
            result.update({"status": "success", **parsed})
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
        LOG.info("operation=get_health status=%s overall=%s mock=%s",
                 result["status"], result["overall"], self.mock)
        return result

    def collect_ospf_status(self, name: str) -> CollectionResult[OspfStatus]:
        """Read OSPF process and adjacency state into a typed result."""
        result = CollectionResult(
            name, "ospf_status", datetime.now(timezone.utc).isoformat(),
            "mock" if self.mock else "live",
        )
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "ospf")
            family = platform.driver
            commands = platform.ospf_status_commands
            mock_outputs = platform.mock_ospf_status
            result.commands = tuple(commands.values())
            outputs, password = self._read_many(
                name, commands, 30, mock_outputs, family
            )
            if password:
                outputs = {
                    key: value.replace(password, "[REDACTED]")
                    for key, value in outputs.items()
                }
            result.data = platform.ospf_status_parser(outputs)
            result.complete = result.data.complete
            result.warnings = result.data.warnings
            result.status = "success" if result.complete else "partial"
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = (
                "unsupported_capability" if result.status == "unsupported"
                else "collection_failed"
            )
            result.error = self.error_mapper(exc)
        return result

    def ospf_status(self, name: str) -> dict:
        """Return the established OSPF response shape."""
        result = ospf_status_legacy(self.collect_ospf_status(name))
        LOG.info(
            "operation=get_ospf_status status=%s running=%s mock=%s",
            result["status"], result["running"], self.mock,
        )
        return result

    def collect_bgp_status(self, name: str) -> CollectionResult[BgpStatus]:
        """Read BGP identity, peer state, prefixes, and Up/Down duration."""
        result = CollectionResult(
            name, "bgp_status", datetime.now(timezone.utc).isoformat(),
            "mock" if self.mock else "live",
        )
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "bgp")
            commands = platform.bgp_status_commands
            mock_outputs = platform.mock_bgp_status
            if not commands or not mock_outputs or not platform.bgp_status_parser:
                raise UnsupportedCapability("BGP status collection is not available for this platform.")
            result.commands = tuple(commands.values())
            outputs, password = self._read_many(
                name, commands, 30, mock_outputs, platform.driver
            )
            if password:
                outputs = {
                    key: value.replace(password, "[REDACTED]")
                    for key, value in outputs.items()
                }
            result.data = platform.bgp_status_parser(outputs)
            result.complete = result.data.complete
            result.warnings = result.data.warnings
            result.status = "success" if result.complete else "partial"
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = (
                "unsupported_capability" if result.status == "unsupported"
                else "collection_failed"
            )
            result.error = self.error_mapper(exc)
        return result

    def bgp_status(self, name: str) -> dict:
        result = bgp_status_legacy(self.collect_bgp_status(name))
        LOG.info(
            "operation=get_bgp_status status=%s established=%s mock=%s",
            result["status"], result["established_count"], self.mock,
        )
        return result

    def bgp_configuration(self, name: str) -> dict:
        """Read only the live BGP configuration section for diagnosis."""
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "bgp")
            command = platform.bgp_configuration_command
            if not command:
                raise UnsupportedCapability(
                    "BGP configuration collection is not available for this platform."
                )
            outputs, password = self._read_many(
                name, {"configuration": command}, 30,
                {"configuration": platform.mock_bgp_configuration or ""},
                platform.driver,
            )
            raw = outputs["configuration"]
            if self.command_rejected(raw):
                raise InventoryError(
                    "BGP configuration command unsupported or not permitted by this device/account."
                )
            output, redactions = sanitize_configuration(raw, password)
            return {
                "device": device.name, "command": command, "timestamp": timestamp,
                "status": "success", "output": output, "redactions": redactions,
                "mock": self.mock,
            }
        except Exception as exc:
            return {
                "device": name, "command": None, "timestamp": timestamp,
                "status": "error", "output": "", "redactions": 0,
                "error": self.error_mapper(exc), "mock": self.mock,
            }

    def bgp_routes(self, name: str) -> dict:
        """Read the current vendor BGP routing table with a fixed command."""
        timestamp = datetime.now(timezone.utc).isoformat()
        command = None
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.require(device, "bgp")
            command = platform.bgp_routes_command
            if not command:
                raise UnsupportedCapability("BGP route collection is not available for this platform.")
            outputs, password = self._read_many(
                name, {"routes": command}, 30,
                {"routes": platform.mock_bgp_routes or ""}, platform.driver,
            )
            output = outputs["routes"]
            if password:
                output = output.replace(password, "[REDACTED]")
            if self.command_rejected(output):
                raise InventoryError(
                    "BGP route command unsupported or not permitted by this device/account."
                )
            truncated = len(output) > self.max_output
            return {
                "device": device.name, "command": command, "timestamp": timestamp,
                "status": "success", "output": output[:self.max_output]
                + ("\n[OUTPUT TRUNCATED]" if truncated else ""),
                "truncated": truncated, "mock": self.mock,
            }
        except Exception as exc:
            return {
                "device": name, "command": command, "timestamp": timestamp,
                "status": "error", "output": "", "truncated": False,
                "error": self.error_mapper(exc), "mock": self.mock,
            }

    def collect_configuration(
        self, name: str, source: str = "running"
    ) -> CollectionResult[ConfigurationSnapshot]:
        """Fetch a sanitized configuration into a typed collection result."""
        try:
            platform = self.capabilities.require(
                self.inventory.get(name), "configuration"
            )
            family = platform.driver
        except Exception as exc:
            platform = None
            family = ""
            family_error = exc
        else:
            family_error = None
        config_commands = {} if platform is None else platform.configuration_commands
        command = config_commands.get(source)
        result = CollectionResult(
            name, "configuration", datetime.now(timezone.utc).isoformat(),
            "mock" if self.mock else "live",
            data=ConfigurationSnapshot(source, "", None, 0, 0, 0),
            commands=() if command is None else (command,),
        )
        try:
            if family_error:
                raise family_error
            if command is None:
                source_error = (platform.configuration_errors or {}).get(source)
                if source_error:
                    raise InventoryError(source_error)
                raise InventoryError("Unsupported configuration source; use running or startup.")
            raw, password = self._read_many(
                name, {"result": command}, 60,
                {"result": platform.mock_configurations[source]}, family
            )
            raw = raw["result"]
            if self.command_rejected(raw):
                result.error = "Configuration command unsupported or not permitted by this device/account."
                result.error_code = "command_rejected"
                return result
            output, redactions = sanitize_configuration(raw, password)
            result.data = ConfigurationSnapshot(
                source=source,
                output=output,
                revision=hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
                total_chars=len(output),
                total_lines=len(output.splitlines()),
                redactions=redactions,
            )
            result.status = "success"
            result.complete = True
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = (
                "unsupported_capability" if result.status == "unsupported"
                else "collection_failed"
            )
            result.error = self.error_mapper(exc)
        return result

    def collect_vpn_status(self, name: str) -> CollectionResult[VpnStatus]:
        """Read FortiOS IPsec and SSL-VPN operational state into a typed result."""
        result = CollectionResult(
            name, "vpn_status", datetime.now(timezone.utc).isoformat(),
            "mock" if self.mock else "live",
        )
        try:
            device = self.inventory.get(name)
            platform = self.capabilities.platform_for(device)
            if platform is None or "vpn" not in platform.capabilities:
                raise UnsupportedCapability(
                    "VPN status collection currently supports Fortinet FortiOS inventory records."
                )
            collector = platform.vpn_collector
            if collector is None:
                raise UnsupportedCapability("VPN status collection is not available for this platform.")
            result.commands = tuple(collector.COMMANDS.values())
            outputs, password = self._read_many(
                name, collector.COMMANDS, 60, collector.MOCK_OUTPUTS,
                platform.driver,
            )
            if password:
                outputs = {
                    key: value.replace(password, "[REDACTED]")
                    for key, value in outputs.items()
                }
            result.data = collector.parse_status(outputs)
            result.complete = result.data.complete
            result.warnings = result.data.warnings
            result.status = "success" if result.complete else "partial"
        except Exception as exc:
            result.status = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
            result.error_code = (
                "unsupported_capability" if result.status == "unsupported"
                else "collection_failed"
            )
            result.error = self.error_mapper(exc)
        return result

    def vpn_status(self, name: str) -> dict:
        """Return normalized live VPN status for one supported firewall."""
        result = vpn_status_legacy(self.collect_vpn_status(name))
        LOG.info(
            "operation=get_vpn_status status=%s active=%s mock=%s",
            result["status"], result["has_active_vpn"], self.mock,
        )
        return result

    def configuration(self, name: str, source: str = "running") -> dict:
        """Return the established sanitized configuration response shape."""
        result = configuration_legacy(self.collect_configuration(name, source))
        LOG.info("operation=get_configuration source=%s status=%s mock=%s", source, result["status"], self.mock)
        return result

    def get_configuration(self, name: str, source: str, cursor: int, revision: str) -> dict:
        """Return a revision-checked page from a sanitized configuration."""
        result = self.configuration(name, source)
        output = result.pop("output")
        result.update({"cursor": cursor, "next_cursor": None, "complete": False, "output": ""})
        if result["status"] != "success":
            return result
        if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0 or cursor > len(output):
            result.update({"status": "error", "error": "Invalid configuration cursor."})
            return result
        if revision and revision != result["revision"]:
            result.update({
                "status": "error",
                "error": "Configuration changed between pages; restart with cursor 0 and an empty revision.",
            })
            return result
        end = min(cursor + self.config_page_chars, len(output))
        result["output"] = output[cursor:end]
        result["complete"] = end == len(output)
        result["next_cursor"] = None if result["complete"] else end
        return result
