"""Single-use, scope-bound authorization for live configuration changes."""

from __future__ import annotations

from hashlib import sha256
from threading import Lock

from ..domain.changes import ChangeAuthorization, ChangePlan
from ..domain.errors import InventoryError


class ChangeAuthorizationError(InventoryError):
    pass


def command_hashes(plan: ChangePlan, action: str) -> tuple[str, ...]:
    groups = (
        row.commands if action == "apply" else
        row.save_commands if action == "save" else
        row.rollback.commands
        for row in plan.devices
    )
    return tuple(
        sha256("\0".join(commands).encode("utf-8")).hexdigest()
        for commands in groups
    )


class ChangeWritePolicy:
    def __init__(self):
        self._issuer = object()
        self._active: set[object] = set()
        self._lock = Lock()

    def authorize(self, plan: ChangePlan, action: str) -> ChangeAuthorization:
        if action not in {"apply", "save", "rollback"}:
            raise ChangeAuthorizationError("Unsupported change authorization action.")
        expected = "prepared" if action == "apply" else "applied_pending_save"
        if plan.state != expected:
            raise ChangeAuthorizationError(
                f"Change must be {expected} before it can be {action}d."
            )
        nonce = object()
        with self._lock:
            self._active.add(nonce)
        return ChangeAuthorization._issue(
            plan.change_id, plan.revision, action,
            tuple(row.device.casefold() for row in plan.devices),
            command_hashes(plan, action), self._issuer, nonce,
        )

    def require(self, authorization: ChangeAuthorization, plan: ChangePlan,
                action: str) -> None:
        actual = (
            getattr(authorization, "change_id", None),
            getattr(authorization, "revision", None),
            getattr(authorization, "action", None),
            getattr(authorization, "devices", None),
            getattr(authorization, "command_hashes", None),
        )
        expected = (
            plan.change_id, plan.revision, action,
            tuple(row.device.casefold() for row in plan.devices),
            command_hashes(plan, action),
        )
        valid = (
            isinstance(authorization, ChangeAuthorization)
            and authorization._issuer is self._issuer and actual == expected
        )
        if valid:
            with self._lock:
                valid = authorization._nonce in self._active
                self._active.discard(authorization._nonce)
        if not valid:
            raise ChangeAuthorizationError(
                "Change authorization is missing, reused, or does not match the plan."
            )
