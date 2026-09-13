"""Planning, querying, and authorized execution of configuration changes."""

from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..domain.changes import (
    CHANGE_KINDS, ChangeOperation, ChangePlan, ChangeRequest, ChangeResult, DeviceChangePlan,
    RollbackPlan, VerificationCheck,
)
from ..domain.errors import InventoryError
from .change_policy import ChangeWritePolicy
from .inspection import sanitize_configuration


MAX_OPERATIONS = 100


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _configuration_revision(outputs: dict[str, str], commands: tuple[str, ...]) -> str:
    """Hash configuration state while excluding volatile status such as uptime."""
    stable = {
        str(index): outputs.get(str(index), "")
        for index, command in enumerate(commands)
        if "config" in command.casefold() or command.strip().casefold() == "show"
    }
    if not stable:
        raise InventoryError("The platform preflight has no stable configuration source.")
    return _digest(stable)


def _resolve_interface_operation(operation: ChangeOperation, configuration: str) -> ChangeOperation:
    """Resolve an abbreviated interface only when live configuration has one match."""
    if operation.kind not in {
        "interface_description", "interface_admin", "interface_ipv4", "interface_delete", "access_vlan",
        "bgp_interface_network",
        "ospf_interface", "acl_attach",
    }:
        return operation
    values = dict(operation.values)
    requested = str(values.get("interface", "")).strip()
    headers = [
        line.strip().split(None, 1)[1] for line in configuration.splitlines()
        if re.match(r"(?i)^interface\s+\S+", line.strip())
    ]
    exact = [name for name in headers if name.casefold() == requested.casefold()]
    candidates = exact
    previous = values.pop("previous_address", None)
    if not candidates and previous:
        address_pattern = re.compile(
            rf"(?im)^\s*ip address\s+{re.escape(str(previous))}(?:\s|/|$)"
        )
        candidates = []
        lines = configuration.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"(?i)^interface\s+(\S+)", line.strip())
            if not match:
                continue
            end = next((i for i in range(index + 1, len(lines))
                        if lines[i] and not lines[i][0].isspace()), len(lines))
            if address_pattern.search("\n".join(lines[index + 1:end])):
                candidates.append(match.group(1))
    # A fully qualified network interface commonly ends in a unit number. It can
    # be valid even when a platform omits an otherwise empty interface stanza.
    if not candidates and re.search(r"\d$", requested):
        candidates = [requested]
    if not candidates:
        candidates = [name for name in headers if name.casefold().startswith(requested.casefold())]
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) != 1:
        detail = "no matching interface" if not candidates else "matches " + ", ".join(candidates)
        raise InventoryError(f"Interface {requested!r} is ambiguous or unknown: {detail}.")
    values["interface"] = candidates[0]
    return ChangeOperation(operation.kind, values, operation.device)


def _resolve_derived_operation(operation: ChangeOperation, configuration: str) -> ChangeOperation:
    """Resolve interface-referenced intent into an exact BGP network operation."""
    operation = _resolve_interface_operation(operation, configuration)
    if operation.kind != "bgp_interface_network":
        return operation
    interface = operation.values["interface"]
    _header, scope = _configuration_scope(
        ChangeOperation("interface_ipv4", {"interface": interface}, operation.device),
        configuration,
    )
    networks = set()
    for line in scope:
        match = re.match(r"(?i)^ip address\s+(\S+)(?:\s+(\S+))?", line)
        if not match or match.group(1).casefold() in {"dhcp", "negotiated"}:
            continue
        try:
            suffix = match.group(2) or "32"
            networks.add(ipaddress.ip_interface(f"{match.group(1)}/{suffix}").network)
        except ValueError:
            continue
    if len(networks) != 1:
        raise InventoryError(
            f"Interface {interface} must have exactly one supported live IPv4 address to advertise."
        )
    local_as = {
        int(match.group(1)) for line in configuration.splitlines()
        if (match := re.match(r"(?i)^router bgp\s+(\d+)$", line.strip()))
    }
    if len(local_as) != 1:
        raise InventoryError("The device must have exactly one supported BGP process.")
    return ChangeOperation(
        "bgp_network",
        {"local_as": local_as.pop(), "prefix": str(networks.pop()),
         "present": operation.values.get("present", True)},
        operation.device,
    )


def _configuration_scope(operation: ChangeOperation, configuration: str) -> tuple[str, tuple[str, ...]]:
    """Return the relevant live hierarchy and its child lines."""
    values, kind = operation.values, operation.kind
    if kind.startswith("interface_") or kind in {"access_vlan", "ospf_interface", "acl_attach"}:
        header = f"interface {values['interface']}"
    elif kind == "ospf_network":
        header = f"router ospf {values['process_id']}"
    elif kind.startswith("bgp_"):
        header = f"router bgp {values['local_as']}"
    elif kind == "acl_rule":
        header = f"ip access-list extended {values['acl_name']}"
    elif kind == "vlan":
        header = f"vlan {values['vlan_id']}"
    else:
        return "", tuple(line.strip() for line in configuration.splitlines() if line.strip())
    lines = configuration.splitlines()
    for index, line in enumerate(lines):
        if line.strip().casefold() != header.casefold():
            continue
        children = []
        for child in lines[index + 1:]:
            if child and not child[0].isspace():
                break
            if child.strip() and child.strip() != "!":
                children.append(child.strip())
        return header, tuple(children)
    return header, ()


def _current_conflicts(operation: ChangeOperation, scope: tuple[str, ...]) -> tuple[str, ...]:
    kind, values = operation.kind, operation.values
    prefixes = {
        "interface_description": ("description ",),
        "interface_admin": ("shutdown",),
        "interface_ipv4": ("ip address ",),
        "access_vlan": ("switchport access vlan ",),
        "ospf_interface": ("ip ospf ",),
        "acl_attach": ("ip access-group ",),
        "ospf_network": ("network ",),
        "bgp_neighbor": tuple(filter(None, (
            f"neighbor {values.get('neighbor', '')} remote-as ",
            (f"neighbor {values.get('neighbor', '')} update-source "
             if values.get("update_source") else ""),
        ))),
        "bgp_network": ("network ",),
        "acl_rule": (f"{values.get('sequence', '')} ",),
        "static_route": ("ip route ",),
        "ntp_server": ("ntp server ",),
        "dns_server": ("ip name-server ",),
        "syslog_server": ("logging host ",),
        "vlan": ("name ",),
    }.get(kind, ())
    return tuple(line for line in scope if any(line.casefold().startswith(p.casefold()) for p in prefixes))


def _operation_diff(operation: ChangeOperation, rendered, configuration: str):
    header, scope = _configuration_scope(operation, configuration)
    if operation.kind == "interface_delete":
        exists = any(
            line.strip().casefold() == header.casefold()
            for line in configuration.splitlines()
        )
        if not exists:
            return True, ("  (the interface is absent in live configuration)",)
        return False, tuple(["- " + header, *("- " + line for line in scope)])
    satisfied = (
        all(item.strip() in scope for item in rendered.expected)
        and all(item.strip() not in scope for item in rendered.excluded)
    )
    context = ["  " + header] if header else []
    if satisfied:
        current = ["  " + line for line in rendered.expected]
        if not current and rendered.excluded:
            current = ["  (the removed setting is absent in live configuration)"]
        return True, tuple(context + current)
    conflicting = _current_conflicts(operation, scope)
    diff = context + ["- " + line for line in conflicting if line not in rendered.expected]
    for index, command in enumerate(rendered.commands):
        lowered = command.casefold()
        if index == 0 and header and lowered == header.casefold():
            continue
        if lowered.startswith("no "):
            desired = command[3:]
            if desired not in conflicting:
                diff.append("- " + desired)
        elif lowered.startswith(("unset ", "delete ")):
            desired = command.split(" ", 1)[1]
            if desired not in conflicting:
                diff.append("- " + desired)
        elif lowered in {"end", "next", "exit"}:
            diff.append("  " + command)
        else:
            diff.append("+ " + command)
    return False, tuple(dict.fromkeys(diff))


def _validate_live_dependencies(operation: ChangeOperation, configuration: str) -> None:
    if operation.kind == "interface_delete":
        interface = str(operation.values.get("interface", ""))
        header = re.compile(rf"(?im)^interface\s+{re.escape(interface)}\s*$")
        match = header.search(configuration)
        own_start = match.start() if match else -1
        own_end = len(configuration)
        if match:
            following = re.search(r"(?m)^\S", configuration[match.end():])
            own_end = match.end() + (following.start() if following else len(configuration[match.end():]))
        outside = configuration[:own_start] + configuration[own_end:] if match else configuration
        references = [
            line.strip() for line in outside.splitlines()
            if re.search(rf"(?i)(?<![\w./-]){re.escape(interface)}(?![\w./-])", line)
        ]
        if references:
            raise InventoryError(
                f"Cannot delete {interface} while other configuration references it: "
                + "; ".join(references[:3])
            )
        return
    if operation.kind != "interface_ipv4":
        return
    interface = str(operation.values.get("interface", ""))
    if "." in interface:
        return
    subinterface = re.compile(
        rf"(?im)^interface\s+{re.escape(interface)}\.\S+\s*$"
    )
    matches = tuple(match.group(0).split(None, 1)[1] for match in subinterface.finditer(configuration))
    if matches:
        raise InventoryError(
            f"Cannot change the parent IPv4 address on {interface} while subinterfaces exist: "
            + ", ".join(matches)
        )


def _plan_from_dict(value: dict) -> ChangePlan:
    request = value["request"]
    device_plans = []
    for row in value["devices"]:
        rollback = row["rollback"]
        device_plans.append(DeviceChangePlan(
            device=row["device"], platform=row["platform"],
            commands=tuple(row["commands"]),
            verification=tuple(VerificationCheck(**check) for check in row["verification"]),
            rollback=RollbackPlan(
                checkpoint_create=tuple(rollback["checkpoint_create"]),
                commands=tuple(rollback["commands"]),
                verification=tuple(VerificationCheck(**check) for check in rollback["verification"]),
                checkpoint_cleanup=tuple(rollback.get("checkpoint_cleanup", ())),
            ),
            save_commands=tuple(row["save_commands"]),
            preflight_commands=tuple(row["preflight_commands"]),
            state_revision=row["state_revision"], impact=tuple(row.get("impact", ())),
            configuration_diff=tuple(row.get("configuration_diff", ())),
            already_applied=bool(row.get("already_applied", False)),
        ))
    return ChangePlan(
        change_id=value["change_id"], revision=value["revision"], state=value["state"],
        created_at=value["created_at"],
        request=ChangeRequest(
            devices=tuple(request["devices"]),
            operations=tuple(ChangeOperation(**op) for op in request["operations"]),
            summary=request.get("summary", ""),
        ), devices=tuple(device_plans),
    )


def parse_structured_request(payload: str | Path, devices: tuple[str, ...]) -> ChangeRequest:
    """Load a strict JSON request. Raw CLI commands have no representation."""
    text = Path(payload).read_text(encoding="utf-8-sig") if isinstance(payload, Path) else payload
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InventoryError(
            "The request is not structured JSON. Use --file, or configure OpenAI for natural-language planning."
        ) from exc
    if isinstance(data, list):
        data = {"operations": data}
    if not isinstance(data, dict) or set(data) - {"summary", "operations", "devices"}:
        raise InventoryError("Change request contains unsupported fields.")
    requested_devices = tuple(data.get("devices") or devices)
    if not requested_devices:
        raise InventoryError("At least one device is required.")
    operations = data.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise InventoryError(f"A change requires 1-{MAX_OPERATIONS} operations.")
    parsed = []
    for number, operation in enumerate(operations, 1):
        if (not isinstance(operation, dict)
                or not {"kind", "values"} <= set(operation)
                or set(operation) - {"kind", "values", "device"}):
            raise InventoryError(
                f"Operation {number} must contain only kind and values, with optional device."
            )
        if operation["kind"] not in CHANGE_KINDS or not isinstance(operation["values"], dict):
            raise InventoryError(f"Operation {number} is not an allowlisted typed operation.")
        values = dict(operation["values"])
        nested_target = values.pop("device", None)
        target = operation.get("device", nested_target)
        if (operation.get("device") is not None and nested_target is not None
                and str(operation["device"]).casefold() != str(nested_target).casefold()):
            raise InventoryError(f"Operation {number} contains conflicting device targets.")
        if target is not None and str(target).casefold() not in {
                device.casefold() for device in requested_devices}:
            raise InventoryError(f"Operation {number} names a device outside the target scope.")
        parsed.append(ChangeOperation(
            operation["kind"], values, None if target is None else str(target)
        ))
    summary = str(data.get("summary", ""))[:500]
    if re.search(r"[\x00-\x1f\x7f]", summary) or re.search(
            r"(?i)\b(?:password|secret|community|private-key|pre-shared|psk|token)\b", summary):
        raise InventoryError("Change summaries cannot contain secrets or control characters.")
    return ChangeRequest(requested_devices, tuple(parsed), summary)


def _normalize_translated_values(kind: str, values: dict[str, Any], number: int) -> dict[str, Any]:
    """Normalize harmless model aliases before strict adapter validation."""
    normalized = dict(values)
    if kind != "interface_ipv4":
        return normalized
    # The old address is context, never desired state. Validate it before dropping
    # it; preflight independently discovers the actual live value for the diff.
    for alias in ("previous_address", "old_address", "previous_ip", "old_ip"):
        if alias not in normalized:
            continue
        previous = str(normalized.pop(alias)).strip()
        try:
            ipaddress.ip_interface(previous if "/" in previous else previous + "/32")
        except ValueError as exc:
            raise InventoryError(
                f"Operation {number} contains an invalid previous interface address."
            ) from exc
        normalized["previous_address"] = previous.split("/", 1)[0]
    normalized.pop("previous_prefix_length", None)
    if "ipv4" in normalized:
        ipv4 = normalized.pop("ipv4")
        if isinstance(ipv4, dict):
            unknown = set(ipv4) - {"address", "ip_address", "prefix", "prefix_length", "subnet_mask"}
            if unknown:
                raise InventoryError(
                    f"Operation {number} contains unsupported IPv4 value(s): "
                    + ", ".join(sorted(unknown))
                )
            for key, value in ipv4.items():
                if key in normalized and normalized[key] != value:
                    raise InventoryError(f"Operation {number} contains conflicting IPv4 values.")
                normalized[key] = value
        elif "address" not in normalized and "ip_address" not in normalized:
            normalized["address"] = ipv4
        elif str(ipv4) not in {str(normalized.get("address")), str(normalized.get("ip_address"))}:
            raise InventoryError(f"Operation {number} contains conflicting IPv4 addresses.")
    if "address" not in normalized and "ip_address" in normalized:
        normalized["address"] = normalized.pop("ip_address")
    if "prefix_length" not in normalized and "prefix" in normalized:
        normalized["prefix_length"] = normalized.pop("prefix")
    address = str(normalized.get("address", ""))
    if "/" in address:
        try:
            interface = ipaddress.ip_interface(address)
        except ValueError as exc:
            raise InventoryError(f"Model returned an invalid interface address for operation {number}.") from exc
        normalized["address"] = str(interface.ip)
        cidr_prefix = interface.network.prefixlen
        existing = normalized.get("prefix_length")
        if existing is not None:
            try:
                conflicts = int(existing) != cidr_prefix
            except (TypeError, ValueError) as exc:
                raise InventoryError(f"Operation {number} contains an invalid prefix length.") from exc
            if conflicts:
                raise InventoryError(f"Operation {number} contains conflicting prefix lengths.")
        normalized["prefix_length"] = cidr_prefix
    if "prefix_length" not in normalized and "subnet_mask" in normalized:
        try:
            normalized["prefix_length"] = ipaddress.ip_network(
                f"0.0.0.0/{normalized.pop('subnet_mask')}"
            ).prefixlen
        except ValueError as exc:
            raise InventoryError(f"Model returned an invalid subnet mask for operation {number}.") from exc
    return normalized


def translate_request(text: str, devices: tuple[str, ...], model: str) -> ChangeRequest:
    """Translate natural language to the same strict operation schema."""
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise InventoryError("Natural-language planning requires the chat optional dependencies.") from exc
    schema = {
        "type": "object", "additionalProperties": False,
        "properties": {
            "summary": {"type": "string"},
            "operations": {"type": "array", "minItems": 1, "maxItems": MAX_OPERATIONS,
                "items": {"type": "object", "additionalProperties": False,
                    "properties": {"kind": {"type": "string", "enum": sorted(CHANGE_KINDS)},
                                   "values_json": {"type": "string"}},
                    "required": ["kind", "values_json"]}},
        }, "required": ["summary", "operations"],
    }
    with OpenAI(timeout=60, max_retries=1) as client:
        response = client.responses.create(
            model=model,
            instructions=(
                "Translate the operator request into allowlisted network desired-state operations. "
                "Put each operation's values object into values_json as strict JSON. Never emit device "
                "commands, credentials, AAA, management-interface, or management-ACL changes. Use only "
                "facts explicitly stated by the operator; do not guess identifiers or current values. "
                "For a loopback-sourced BGP neighbor, put the interface name in update_source. "
                "When more than one target device is provided, every values_json object must include "
                "the exact target inventory name in a device field. For interface_ipv4 use only "
                "interface, address, prefix_length, and optional present; put CIDR in address or use "
                "an integer prefix_length. Do not emit previous_address or an ipv4 wrapper."
                " Use interface_delete with only interface to delete a numbered logical interface."
                " Use bgp_interface_network with interface and optional present when the operator "
                "asks to advertise or withdraw an interface in BGP; do not guess its subnet or AS."
            ), input=text,
            text={"format": {"type": "json_schema", "name": "nerd_change_request",
                             "strict": True, "schema": schema}},
        )
    translated = json.loads(response.output_text)
    operations = []
    for number, operation in enumerate(translated["operations"], 1):
        try:
            values = json.loads(operation["values_json"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise InventoryError(f"Model returned invalid values for operation {number}.") from exc
        if not isinstance(values, dict):
            raise InventoryError(f"Model returned invalid values for operation {number}.")
        # Natural-language multi-device changes bind every operation to one target.
        translated_device = values.pop("device", None)
        if translated_device is not None and str(translated_device).casefold() not in {
                device.casefold() for device in devices}:
            raise InventoryError(
                f"Operation {number} names a device outside the approved target scope."
            )
        if len(devices) > 1:
            if translated_device is None:
                raise InventoryError(
                    f"Operation {number} must name its target device in a multi-device change."
                )
        values = _normalize_translated_values(operation["kind"], values, number)
        operations.append({
            "kind": operation["kind"], "values": values,
            "device": None if translated_device is None else str(translated_device),
        })
    return parse_structured_request(
        json.dumps({"summary": translated["summary"], "operations": operations}), devices
    )


class ChangePlanningService:
    def __init__(self, inventory, repository, transport, registry, adapter_provider,
                 command_failed, safe_error, mock=False):
        self.inventory, self.repository, self.transport = inventory, repository, transport
        self.registry, self.adapter_provider = registry, adapter_provider
        self.command_failed, self.safe_error, self.mock = command_failed, safe_error, mock

    def plan(self, request: ChangeRequest) -> dict:
        canonical = []
        seen = set()
        for name in request.devices:
            device = self.inventory.get(name)
            if device.name.casefold() in seen:
                raise InventoryError("A change cannot name the same device more than once.")
            seen.add(device.name.casefold()); canonical.append(device)
        operations = request.operations
        if len(canonical) == 1:
            # Defense in depth for callers other than the OpenAI translator: the
            # target belongs to ChangeRequest.devices, but a matching duplicate
            # emitted inside an operation is harmless and can be normalized away.
            normalized = []
            for number, operation in enumerate(operations, 1):
                values = dict(operation.values)
                repeated = operation.device
                if repeated is not None and str(repeated).casefold() != canonical[0].name.casefold():
                    raise InventoryError(
                        f"Operation {number} names a device outside the approved target scope."
                    )
                normalized.append(ChangeOperation(operation.kind, values, canonical[0].name))
            operations = tuple(normalized)
        change_id = "CHG-" + uuid4().hex[:12].upper()
        device_plans = []
        for device in canonical:
            platform = self.registry.platform_for(device)
            if platform is None:
                raise InventoryError(f"{device.name} has no recognized platform adapter.")
            adapter = self.adapter_provider(platform)
            if adapter.immediate_persistence and not adapter.checkpoint_supported:
                raise InventoryError(
                    f"{device.name} remains read-only: {adapter.platform} has no verified "
                    "transaction/checkpoint implementation."
                )
            selected_operations = []
            for operation in operations:
                values = dict(operation.values)
                target = operation.device
                if target is not None and str(target).casefold() != device.name.casefold():
                    continue
                selected_operations.append(ChangeOperation(operation.kind, values, device.name))
            if self.mock:
                mock_config = "\n".join(
                    f"interface {operation.values['interface']}"
                    for operation in selected_operations if operation.values.get("interface")
                ) or f"hostname {device.name}"
                outputs = {
                    str(index): (
                        mock_config if "config" in command.casefold()
                        else f"mock:{device.name}:{command}"
                    )
                    for index, command in enumerate(adapter.preflight_commands)
                }
            else:
                try:
                    outputs, _ = self.transport.read_many(
                        device, platform.driver,
                        {str(i): command for i, command in enumerate(adapter.preflight_commands)}, 60,
                    )
                except Exception as exc:
                    raise InventoryError(
                        f"Preflight failed on {device.name}: {self.safe_error(exc)}"
                    ) from None
            if any(self.command_failed(output) for output in outputs.values()):
                raise InventoryError(f"Preflight command failed on {device.name}; no plan was stored.")
            running_index = next(
                (str(index) for index, command in enumerate(adapter.preflight_commands)
                 if "running-config" in command.casefold() or command.casefold() == "show"),
                None,
            )
            running = "" if running_index is None else outputs.get(running_index, "")
            sanitized_running, _ = sanitize_configuration(running)
            device_operations = [
                _resolve_derived_operation(operation, sanitized_running)
                for operation in selected_operations
            ]
            rendered = [adapter.render(operation) for operation in device_operations]
            state_revision = _configuration_revision(outputs, adapter.preflight_commands)
            for operation in device_operations:
                _validate_live_dependencies(operation, sanitized_running)
            comparisons = [
                _operation_diff(operation, result, sanitized_running)
                for operation, result in zip(device_operations, rendered)
            ]
            pending = [
                (operation, result, diff) for operation, result, (satisfied, diff)
                in zip(device_operations, rendered, comparisons) if not satisfied
            ]
            create, rollback, cleanup = adapter.checkpoint(change_id)
            if not create or not rollback:
                raise InventoryError(f"{device.name} has no safe rollback implementation.")
            checks = tuple(VerificationCheck(
                "show running-config", row.expected, row.excluded
            ) for _operation, row, _diff in pending)
            diff = [line for _operation, _row, lines in pending for line in lines]
            already_applied = not pending
            if already_applied:
                diff = [line for _satisfied, lines in comparisons for line in lines]
            device_plans.append(DeviceChangePlan(
                device=device.name, platform=platform.name,
                commands=tuple(command for _operation, row, _diff in pending for command in row.commands),
                verification=checks,
                rollback=RollbackPlan(create, rollback, (), cleanup),
                save_commands=adapter.save_commands,
                preflight_commands=adapter.preflight_commands,
                state_revision=state_revision,
                impact=tuple(row.impact for _operation, row, _diff in pending),
                configuration_diff=tuple(diff),
                already_applied=already_applied,
            ))
        created = datetime.now(timezone.utc).isoformat()
        normalized_request = ChangeRequest(
            tuple(device.name for device in canonical), operations, request.summary
        )
        unsigned = {"request": asdict(normalized_request), "devices": [asdict(row) for row in device_plans]}
        revision = _digest(unsigned)
        state = "already_applied" if all(row.already_applied for row in device_plans) else "prepared"
        plan = ChangePlan(change_id, revision, state, created, normalized_request, tuple(device_plans))
        self.repository.put(plan.to_dict())
        return plan.to_dict()


class ChangeQueryService:
    def __init__(self, repository): self.repository = repository
    def get(self, change_id):
        result = self.repository.get(change_id); result["events"] = self.repository.events(change_id); return result
    def history(self): return self.repository.history()


class ChangeWriteService:
    def __init__(self, inventory, repository, transport, registry, command_failed, safe_error,
                 mock=False, policy=None):
        self.inventory, self.repository, self.transport = inventory, repository, transport
        self.registry, self.command_failed, self.safe_error, self.mock = registry, command_failed, safe_error, mock
        self.policy = policy or ChangeWritePolicy()

    def purge(self, before):
        """Delete audit history only after the terminal UI obtains confirmation."""
        return self.repository.purge(before)

    def authorize(self, change_id, action):
        plan = _plan_from_dict(self.repository.get(change_id))
        authorization = self.policy.authorize(plan, action)
        self.repository.event(change_id, f"{action}_approved", {
            "revision": plan.revision,
            "command_hashes": list(authorization.command_hashes),
        })
        return authorization

    def _revision(self, device, row, platform):
        outputs, _ = self.transport.read_many(
            device, platform.driver,
            {str(i): command for i, command in enumerate(row.preflight_commands)}, 60,
        )
        return _configuration_revision(outputs, row.preflight_commands)

    def _verify(self, device, platform, check):
        verify, _ = self.transport.read_many(
            device, platform.driver, {"verify": check.command}, 60
        )
        body = verify["verify"]
        lines = {line.strip() for line in body.splitlines()}
        passed = (
            not self.command_failed(body)
            and all(item.strip() in lines for item in check.contains)
            and all(item.strip() not in lines for item in check.excludes)
        )
        return passed, body

    @staticmethod
    def _affected_configuration(row, body):
        lines = {line.strip(): line.strip() for line in body.splitlines() if line.strip()}
        headers = tuple(command for command in row.commands if command.casefold().startswith(
            ("interface ", "router ", "vlan ", "ip access-list ", "config ", "edit ")
        ))
        expected = tuple(item for check in row.verification for item in check.contains)
        visible = [item for item in (*headers, *expected) if item.strip() in lines]
        return "\n".join(dict.fromkeys(visible))

    def apply(self, change_id, *, authorization):
        if self.mock:
            raise InventoryError("Mock mode can prepare plans but cannot apply device changes.")
        plan = _plan_from_dict(self.repository.get(change_id))
        self.policy.require(authorization, plan, "apply")
        self.repository.transition(change_id, ("prepared",), "applying", "apply_started")
        touched = []
        results = []
        stage = "preflight"
        current_device = ""
        try:
            for row in plan.devices:
                current_device = row.device
                if row.already_applied:
                    results.append({"device": row.device, "status": "already applied"})
                    continue
                device = self.inventory.get(row.device); platform = self.registry.platform_for(device)
                stage = "stale-state check"
                if self._revision(device, row, platform) != row.state_revision:
                    raise InventoryError(f"Prepared state changed on {row.device}; the plan is stale.")
                stage = "checkpoint"
                self.transport.execute_commands(device, platform.driver, row.rollback.checkpoint_create)
                touched.append((device, platform, row))
                stage = "configuration apply"
                output = self.transport.send_config(device, platform.driver, row.commands)
                if self.command_failed(output): raise InventoryError(f"Device rejected configuration on {row.device}.")
                stage = "post-change verification"
                live_sections = []
                for check in row.verification:
                    passed, body = self._verify(device, platform, check)
                    if not passed:
                        raise InventoryError(f"Post-change verification failed on {row.device}.")
                    section = self._affected_configuration(row, body)
                    if section:
                        live_sections.append(section)
                results.append({
                    "device": row.device, "status": "verified",
                    "commands_completed": len(row.commands),
                    "live_configuration": "\n".join(dict.fromkeys(live_sections)),
                })
                self.repository.event(change_id, "device_verified", {"device": row.device})
        except Exception as exc:
            rollback_failures = []
            self.repository.transition(change_id, ("applying",), "rolling_back", "rollback_started")
            for device, platform, row in reversed(touched):
                try:
                    self.transport.execute_commands(device, platform.driver, row.rollback.commands)
                    if self._revision(device, row, platform) != row.state_revision:
                        raise InventoryError("state revision mismatch")
                    self.transport.execute_commands(device, platform.driver, row.rollback.checkpoint_cleanup)
                    self.repository.event(change_id, "device_rolled_back", {"device": row.device})
                except Exception:
                    rollback_failures.append(row.device)
            message = self.safe_error(exc)
            if rollback_failures:
                message += "; rollback verification failed for: " + ", ".join(rollback_failures)
                state = "failed"
            elif not touched:
                state = "failed"
            else:
                state = "rolled_back"
            self.repository.transition(change_id, ("rolling_back",), state, state, error=message)
            failed = {
                "device": current_device or "unknown", "status": "failed", "stage": stage,
                "reason": message, "rollback": (
                    "failed" if current_device in rollback_failures else
                    "verified" if touched else "not required"
                ),
            }
            return ChangeResult(change_id, state, tuple((*results, failed)), message).to_dict()
        self.repository.transition(change_id, ("applying",), "applied_pending_save", "apply_verified")
        return ChangeResult(change_id, "applied_pending_save", tuple(results)).to_dict()

    def save(self, change_id, *, authorization):
        if self.mock: raise InventoryError("Mock mode cannot save device changes.")
        plan = _plan_from_dict(self.repository.get(change_id))
        self.policy.require(authorization, plan, "save")
        self.repository.transition(change_id, ("applied_pending_save",), "saving", "save_started")
        results = []
        try:
            for row in plan.devices:
                if row.already_applied:
                    results.append({"device": row.device, "status": "already persistent"})
                    continue
                device = self.inventory.get(row.device); platform = self.registry.platform_for(device)
                # Revalidate the desired running state immediately before persistence.
                for check in row.verification:
                    passed, _body = self._verify(device, platform, check)
                    if not passed:
                        raise InventoryError(
                            f"Running state changed before save on {row.device}."
                        )
                self.transport.execute_commands(device, platform.driver, row.save_commands)
                persistent_command = row.preflight_commands[-1]
                persistent, _ = self.transport.read_many(
                    device, platform.driver, {"persistent": persistent_command}, 60
                )
                persistent_body = persistent["persistent"]
                persistent_lines = {line.strip() for line in persistent_body.splitlines()}
                for check in row.verification:
                    if (self.command_failed(persistent_body)
                            or any(item.strip() not in persistent_lines for item in check.contains)
                            or any(item.strip() in persistent_lines for item in check.excludes)):
                        raise InventoryError(
                            f"Persistent-state verification failed on {row.device}."
                        )
                self.transport.execute_commands(
                    device, platform.driver, row.rollback.checkpoint_cleanup
                )
                results.append({"device": row.device, "status": "saved"})
                self.repository.event(change_id, "device_saved", {"device": row.device})
        except Exception as exc:
            message = self.safe_error(exc)
            self.repository.transition(change_id, ("saving",), "failed", "save_failed", error=message)
            return ChangeResult(change_id, "failed", tuple(results), message).to_dict()
        self.repository.transition(change_id, ("saving",), "saved", "save_completed")
        return ChangeResult(change_id, "saved", tuple(results)).to_dict()

    def rollback(self, change_id, *, authorization):
        """Restore the verified pre-change checkpoint before an unsaved change is saved."""
        if self.mock:
            raise InventoryError("Mock mode cannot roll back device changes.")
        plan = _plan_from_dict(self.repository.get(change_id))
        self.policy.require(authorization, plan, "rollback")
        self.repository.transition(
            change_id, ("applied_pending_save",), "rolling_back", "operator_rollback_started"
        )
        results = []
        failures = []
        for row in reversed(plan.devices):
            if row.already_applied:
                results.append({"device": row.device, "status": "unchanged"})
                continue
            try:
                device = self.inventory.get(row.device)
                platform = self.registry.platform_for(device)
                self.transport.execute_commands(device, platform.driver, row.rollback.commands)
                if self._revision(device, row, platform) != row.state_revision:
                    raise InventoryError("restored state did not match the pre-change revision")
                self.transport.execute_commands(
                    device, platform.driver, row.rollback.checkpoint_cleanup
                )
                results.append({"device": row.device, "status": "rollback verified"})
                self.repository.event(change_id, "device_rolled_back", {"device": row.device})
            except Exception as exc:
                reason = self.safe_error(exc)
                failures.append(row.device)
                results.append({
                    "device": row.device, "status": "failed", "stage": "operator rollback",
                    "reason": reason, "rollback": "failed",
                })
        if failures:
            message = "Rollback verification failed for: " + ", ".join(failures)
            self.repository.transition(
                change_id, ("rolling_back",), "failed", "operator_rollback_failed",
                error=message,
            )
            return ChangeResult(change_id, "failed", tuple(results), message).to_dict()
        self.repository.transition(
            change_id, ("rolling_back",), "rolled_back", "operator_rollback_completed"
        )
        return ChangeResult(change_id, "rolled_back", tuple(results)).to_dict()
