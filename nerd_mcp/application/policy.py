"""Scoped authorization for application operations that mutate retained data."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from ..domain.errors import InventoryError
from .operations import OperationEffect, operation


class BaselineAuthorizationError(InventoryError):
    pass


@dataclass(frozen=True, init=False)
class BaselineWriteAuthorization:
    action: str
    devices: tuple[str, ...]
    source: str | None
    replace: bool
    _issuer: object = field(repr=False, compare=False)
    _nonce: object = field(repr=False, compare=False)

    @classmethod
    def _issue(cls, action: str, devices: tuple[str, ...], source: str | None,
               replace: bool, issuer: object, nonce: object) -> BaselineWriteAuthorization:
        authorization = object.__new__(cls)
        object.__setattr__(authorization, "action", action)
        object.__setattr__(authorization, "devices", devices)
        object.__setattr__(authorization, "source", source)
        object.__setattr__(authorization, "replace", replace)
        object.__setattr__(authorization, "_issuer", issuer)
        object.__setattr__(authorization, "_nonce", nonce)
        return authorization


class BaselineWritePolicy:
    """Issue and verify approvals bound to an exact baseline mutation scope."""

    def __init__(self):
        self._issuer = object()
        self._active: set[object] = set()
        self._guard = Lock()

    @staticmethod
    def _devices(devices) -> tuple[str, ...]:
        if isinstance(devices, str):
            devices = (devices,)
        try:
            normalized = tuple(sorted({
                str(device).strip().casefold() for device in devices
                if str(device).strip()
            }))
        except TypeError as exc:
            raise BaselineAuthorizationError("Baseline approval has an invalid device scope.") from exc
        return normalized

    @staticmethod
    def _validate(action: str, source: str | None, replace: bool) -> None:
        try:
            definition = operation(action)
        except KeyError as exc:
            raise BaselineAuthorizationError(
                "The requested operation is not an approved baseline write."
            ) from exc
        if (definition.mcp_exposed
                or OperationEffect.WRITE_BASELINE not in definition.effects):
            raise BaselineAuthorizationError(
                "The requested operation is not an approved baseline write."
            )
        if source not in {None, "running", "startup"}:
            raise BaselineAuthorizationError(
                "Unsupported configuration source; use running or startup."
            )
        if not isinstance(replace, bool):
            raise BaselineAuthorizationError("Replace must be true or false.")
        expected = {
            "capture_configuration_baseline": (source is not None),
            "refresh_configuration_baselines": replace,
            "remove_configuration_baseline": source is None and not replace,
        }
        if not expected.get(action, False):
            raise BaselineAuthorizationError(
                "The baseline approval does not match the operation's write intent."
            )

    def authorize(self, action: str, devices, *, source: str | None,
                  replace: bool) -> BaselineWriteAuthorization:
        """Create the scoped proof after an interface has obtained user approval."""
        self._validate(action, source, replace)
        nonce = object()
        with self._guard:
            self._active.add(nonce)
        return BaselineWriteAuthorization._issue(
            action, self._devices(devices), source, replace, self._issuer, nonce
        )

    def require(self, authorization: BaselineWriteAuthorization, action: str,
                devices, *, source: str | None, replace: bool) -> None:
        self._validate(action, source, replace)
        expected = (action, self._devices(devices), source, replace)
        actual = (
            getattr(authorization, "action", None),
            getattr(authorization, "devices", None),
            getattr(authorization, "source", None),
            getattr(authorization, "replace", None),
        )
        valid = (
            isinstance(authorization, BaselineWriteAuthorization)
            and authorization._issuer is self._issuer and actual == expected
        )
        if valid:
            with self._guard:
                valid = authorization._nonce in self._active
                self._active.discard(authorization._nonce)
        if not valid:
            raise BaselineAuthorizationError(
                "Baseline write authorization is missing or does not match the requested operation."
            )
