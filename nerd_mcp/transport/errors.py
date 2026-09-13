"""Public, secret-safe device transport error mapping."""

from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from paramiko import SSHException

from ..domain.errors import InventoryError


def safe_device_error(exc: Exception) -> str:
    if isinstance(exc, InventoryError):
        return str(exc)
    if isinstance(exc, NetmikoAuthenticationException):
        return "SSH authentication failed; check the credential profile and device account."
    if isinstance(exc, (NetmikoTimeoutException, ReadTimeout, TimeoutError)):
        return "SSH connection or command timed out."
    if isinstance(exc, SSHException):
        return "SSH verification or negotiation failed; check the verified host key and SSH settings."
    if isinstance(exc, OSError):
        return "Unable to reach device or read SSH configuration."
    return "Device operation failed; check device connectivity and SSH configuration."
