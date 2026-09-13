"""Verified Netmiko sessions; command selection belongs to callers.

No prompting, vendor parsing, or device-configuration operations live here.
An injected pool owns pooled sessions; otherwise each context owns its session.
"""

from contextlib import contextmanager
from pathlib import Path
import re

from netmiko import ConnectHandler
from netmiko.exceptions import ReadTimeout

from ..credentials import resolve_credentials
from ..domain.errors import InventoryError
from ..settings import env


def disconnect(connection, logger=None):
    """Best-effort cleanup without exposing exception text or masking failures."""
    try:
        connection.disconnect()
    except Exception:
        if logger is not None:
            logger.warning("SSH cleanup failed")


class NetmikoTransport:
    def __init__(self, connector=None, connection_pool=None, logger=None, *,
                 session_factory=None):
        inherited_factory = getattr(connection_pool, "session_factory", None)
        self.session_factory = (
            session_factory or inherited_factory
            or NetmikoSessionFactory(connector, logger=logger)
        )
        self.connector = self.session_factory.connector
        self.connection_pool = connection_pool
        self.logger = logger

    def connect(self, device, device_type, username, password, read_timeout):
        """Compatibility forwarding method for callers that opened raw sessions."""
        return self.session_factory.connect(
            device, device_type, username, password, read_timeout
        )

    @contextmanager
    def connection(self, device, device_type, read_timeout=60):
        """Yield a session and redaction password with explicit ownership."""
        if self.connection_pool is not None:
            with self.connection_pool.connection(device, device_type, read_timeout) as session:
                yield session
            return
        with self.session_factory.connection(device, device_type, read_timeout) as session:
            yield session

    def read_many(self, device, device_type, commands, read_timeout,
                  *, retry_pooled_timeout=False):
        """Read a caller-selected command batch, preserving opt-in pooled retry.

        Only existing Network operations opt in. A retry repeats the whole batch
        after the pool invalidates the failed connection; no other errors retry.
        """
        attempts = 2 if retry_pooled_timeout and self.connection_pool is not None else 1
        for attempt in range(attempts):
            try:
                with self.connection(device, device_type, read_timeout) as (connection, password):
                    return {
                        key: str(connection.send_command(command, read_timeout=read_timeout))
                        for key, command in commands.items()
                    }, password
            except ReadTimeout:
                if attempt + 1 == attempts:
                    raise
                if self.logger is not None:
                    self.logger.info(
                        "operation=ssh_read retry=1 device=%s platform=%s",
                        device.name, device_type,
                    )

    def execute_commands(self, device, device_type, commands, read_timeout=60):
        """Run bounded privileged exec commands on one verified session."""
        if not commands:
            return ()
        with self.connection(device, device_type, read_timeout) as (connection, password):
            outputs = []
            for command in commands:
                interactive = re.match(
                    r"(?i)^(?:copy\s|delete\s|erase\s)", command
                ) and hasattr(connection, "send_command_timing")
                sender = connection.send_command_timing if interactive else connection.send_command
                output = str(sender(command, read_timeout=read_timeout))
                # Unique checkpoint names make accepting the default destination safe.
                # Bound the interaction so an unexpected prompt cannot loop indefinitely.
                for _ in range(2):
                    if not interactive or not re.search(
                            r"(?i)(?:\[confirm\]|destination filename.*\?|continue.*\?)\s*$", output):
                        break
                    output += str(connection.send_command_timing("\n", read_timeout=read_timeout))
                outputs.append(output.replace(password, "[REDACTED]")[:20000])
            return tuple(outputs)

    def send_config(self, device, device_type, commands, read_timeout=60):
        """Apply an adapter-rendered command set; callers enforce authorization."""
        if not commands:
            raise InventoryError("A configuration command set cannot be empty.")
        with self.connection(device, device_type, read_timeout) as (connection, password):
            output = str(connection.send_config_set(
                list(commands), read_timeout=read_timeout, cmd_verify=True,
            ))
            return output.replace(password, "[REDACTED]")[:50000]


class NetmikoSessionFactory:
    """Own strict connection options, credentials, and short-session cleanup."""

    def __init__(self, connector=None, credential_resolver=None,
                 known_hosts_resolver=None, logger=None):
        self.connector = connector or ConnectHandler
        self.credential_resolver = credential_resolver or resolve_credentials
        self.known_hosts_resolver = known_hosts_resolver or self._known_hosts
        self.logger = logger

    @staticmethod
    def _known_hosts() -> Path:
        return Path(env("NERD_KNOWN_HOSTS", "~/.ssh/known_hosts")).expanduser()

    def resolve_credentials(self, profile: str) -> tuple[str, str, str]:
        return self.credential_resolver(profile)

    def connect(self, device, device_type, username, password, read_timeout):
        """Open a verified session; its owner must eventually disconnect it."""
        known_hosts = self.known_hosts_resolver()
        if not known_hosts.is_file():
            raise InventoryError(
                "SSH known_hosts file missing; enroll the verified device host key first."
            )
        return self.connector(
            device_type=device_type, host=device.host, port=device.port,
            username=username, password=password, ssh_strict=True,
            system_host_keys=False, alt_host_keys=True, alt_key_file=str(known_hosts),
            use_keys=False, allow_agent=False, conn_timeout=10, auth_timeout=10,
            banner_timeout=10, blocking_timeout=15, timeout=read_timeout,
            read_timeout_override=read_timeout, session_log=None,
        )

    @contextmanager
    def connection(self, device, device_type, read_timeout=60):
        username, password, _source = self.resolve_credentials(
            device.credential_profile
        )
        connection = self.connect(device, device_type, username, password, read_timeout)
        try:
            yield connection, password
        finally:
            disconnect(connection, self.logger)
