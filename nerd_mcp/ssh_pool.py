"""Bounded, idle-expiring SSH session reuse for the long-running MCP process."""

from __future__ import annotations

import atexit
import hashlib
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from time import monotonic

from .domain.errors import InventoryError
from .domain.inventory import Device
from .transport.netmiko import NetmikoSessionFactory, disconnect


@dataclass
class _Entry:
    connection: object
    last_used: float
    active: bool = False
    credential_token: bytes = b""


class SSHConnectionPool:
    """Reuse verified Netmiko sessions while serializing commands per device."""

    def __init__(self, connector=None, idle_ttl_seconds: float = 60,
                 max_sessions: int = 32, clock=None, register_atexit: bool = True,
                 session_factory=None):
        if idle_ttl_seconds <= 0:
            raise ValueError("idle_ttl_seconds must be positive.")
        if not 1 <= max_sessions <= 256:
            raise ValueError("max_sessions must be between 1 and 256.")
        self.session_factory = session_factory or NetmikoSessionFactory(connector)
        self.connector = self.session_factory.connector
        self.idle_ttl_seconds = float(idle_ttl_seconds)
        self.max_sessions = max_sessions
        self.clock = clock or monotonic
        self._guard = threading.RLock()
        self._locks: dict[tuple, threading.Lock] = {}
        self._entries: dict[tuple, _Entry] = {}
        self._created = 0
        self._reused = 0
        self._expired = 0
        self._invalidated = 0
        if register_atexit:
            atexit.register(self.close_all)

    @staticmethod
    def _key(device: Device, device_type: str) -> tuple:
        return (
            device.host.casefold(), device.port, device.credential_profile.casefold(),
            device_type.casefold(),
        )

    @staticmethod
    def _alive(connection) -> bool:
        checker = getattr(connection, "is_alive", None)
        if not callable(checker):
            return True
        try:
            result = checker()
            return result if isinstance(result, bool) else True
        except Exception:
            return False

    @staticmethod
    def _disconnect(connection) -> None:
        disconnect(connection)

    def _remove(self, key: tuple, *, expired: bool = False,
                invalidated: bool = False) -> None:
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        if expired:
            self._expired += 1
        if invalidated:
            self._invalidated += 1
        self._disconnect(entry.connection)

    def _prune(self, now: float, keep: tuple | None = None) -> None:
        for key, entry in list(self._entries.items()):
            if key != keep and not entry.active and now - entry.last_used >= self.idle_ttl_seconds:
                self._remove(key, expired=True)
        if keep is not None:
            return
        while len(self._entries) >= self.max_sessions:
            candidates = [
                (entry.last_used, key) for key, entry in self._entries.items()
                if key != keep and not entry.active
            ]
            if not candidates:
                raise InventoryError("SSH session pool is at its active-session limit.")
            _last_used, oldest = min(candidates)
            self._remove(oldest, expired=True)

    def _connect(self, device: Device, device_type: str, username: str,
                 password: str, read_timeout: int):
        return self.session_factory.connect(
            device, device_type, username, password, max(60, read_timeout)
        )

    @staticmethod
    def _credential_token(username: str, password: str, source: str) -> bytes:
        material = "\0".join((username, password, source)).encode(
            "utf-8", errors="surrogatepass"
        )
        return hashlib.blake2b(material, digest_size=16).digest()

    @contextmanager
    def connection(self, device: Device, device_type: str, read_timeout: int = 60):
        """Yield one exclusive pooled connection and the current redaction password."""
        username, password, source = self.session_factory.resolve_credentials(
            device.credential_profile
        )
        credential_token = self._credential_token(username, password, source)
        key = self._key(device, device_type)
        with self._guard:
            key_lock = self._locks.setdefault(key, threading.Lock())
        with key_lock:
            now = self.clock()
            create = False
            with self._guard:
                self._prune(now, keep=key)
                entry = self._entries.get(key)
                credential_changed = bool(
                    entry and entry.credential_token != credential_token
                )
                if entry and (
                    now - entry.last_used >= self.idle_ttl_seconds
                    or not self._alive(entry.connection)
                    or credential_changed
                ):
                    self._remove(
                        key, expired=not credential_changed,
                        invalidated=credential_changed,
                    )
                    entry = None
                if entry is None:
                    self._prune(now)
                    entry = _Entry(
                        connection=None, last_used=now, active=True,
                        credential_token=credential_token,
                    )
                    self._entries[key] = entry
                    create = True
                else:
                    entry.active = True
                    self._reused += 1
            if create:
                try:
                    connection = self._connect(
                        device, device_type, username, password, read_timeout
                    )
                except Exception:
                    with self._guard:
                        if self._entries.get(key) is entry:
                            self._entries.pop(key, None)
                    raise
                with self._guard:
                    entry.connection = connection
                    self._created += 1
            try:
                yield entry.connection, password
            except Exception:
                with self._guard:
                    self._remove(key, invalidated=True)
                raise
            else:
                with self._guard:
                    current = self._entries.get(key)
                    if current is entry:
                        current.active = False
                        current.last_used = self.clock()

    def stats(self) -> dict[str, int]:
        with self._guard:
            return {
                "active_sessions": sum(entry.active for entry in self._entries.values()),
                "idle_sessions": sum(not entry.active for entry in self._entries.values()),
                "created": self._created, "reused": self._reused,
                "expired": self._expired, "invalidated": self._invalidated,
            }

    def close_all(self) -> None:
        with self._guard:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            self._disconnect(entry.connection)
