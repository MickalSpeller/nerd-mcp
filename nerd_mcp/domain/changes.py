"""Vendor-neutral configuration change contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


CHANGE_KINDS = frozenset({
    "interface_description", "interface_admin", "interface_ipv4", "interface_delete", "vlan",
    "access_vlan", "static_route", "ospf_network", "ospf_interface",
    "bgp_neighbor", "bgp_network", "bgp_interface_network", "acl_rule", "acl_attach", "ntp_server",
    "dns_server", "syslog_server",
})


ChangeState = Literal[
    "prepared", "already_applied", "applying", "applied_pending_save", "saving", "saved",
    "rolling_back", "rolled_back", "failed",
]


@dataclass(frozen=True)
class ChangeOperation:
    """One allowlisted desired-state operation; never a raw device command."""

    kind: str
    values: dict[str, Any]
    device: str | None = None


@dataclass(frozen=True)
class ChangeRequest:
    devices: tuple[str, ...]
    operations: tuple[ChangeOperation, ...]
    summary: str = ""


@dataclass(frozen=True)
class VerificationCheck:
    command: str
    contains: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RollbackPlan:
    checkpoint_create: tuple[str, ...]
    commands: tuple[str, ...]
    verification: tuple[VerificationCheck, ...]
    checkpoint_cleanup: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeviceChangePlan:
    device: str
    platform: str
    commands: tuple[str, ...]
    verification: tuple[VerificationCheck, ...]
    rollback: RollbackPlan
    save_commands: tuple[str, ...]
    preflight_commands: tuple[str, ...]
    state_revision: str
    impact: tuple[str, ...] = ()
    configuration_diff: tuple[str, ...] = ()
    already_applied: bool = False


@dataclass(frozen=True)
class ChangePlan:
    change_id: str
    revision: str
    state: ChangeState
    created_at: str
    request: ChangeRequest
    devices: tuple[DeviceChangePlan, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, init=False)
class ChangeAuthorization:
    change_id: str
    revision: str
    action: str
    devices: tuple[str, ...]
    command_hashes: tuple[str, ...]
    _issuer: object = field(repr=False, compare=False)
    _nonce: object = field(repr=False, compare=False)

    @classmethod
    def _issue(cls, change_id, revision, action, devices, command_hashes, issuer, nonce):
        value = object.__new__(cls)
        for name, item in {
            "change_id": change_id, "revision": revision, "action": action,
            "devices": devices, "command_hashes": command_hashes,
            "_issuer": issuer, "_nonce": nonce,
        }.items():
            object.__setattr__(value, name, item)
        return value


@dataclass(frozen=True)
class ChangeResult:
    change_id: str
    state: ChangeState
    devices: tuple[dict[str, Any], ...]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
