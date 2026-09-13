"""Explicit SSH host-key enrollment for inventoried devices."""

import base64
import hashlib
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import paramiko

from .domain.errors import InventoryError
from .domain.ports import InventoryReader
from .settings import env


@dataclass(frozen=True)
class HostKeyEnrollmentProposal:
    device: str
    host: str
    port: int
    algorithm: str
    fingerprint: str
    known_hosts: Path
    status: str
    key: paramiko.PKey = field(repr=False)

    def result(self, status: str | None = None) -> dict[str, object]:
        return {
            "device": self.device, "host": self.host, "port": self.port,
            "algorithm": self.algorithm, "fingerprint": self.fingerprint,
            "known_hosts": str(self.known_hosts), "status": status or self.status,
        }


def sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def fetch_host_key(host: str, port: int, timeout: int = 10) -> paramiko.PKey:
    """Retrieve the key presented during SSH negotiation without authenticating."""
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    except (OSError, EOFError, paramiko.SSHException):
        raise InventoryError(
            "Could not retrieve the SSH host key; check the device address, port, SSH service, and connectivity."
        ) from None
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()


def _load_known_hosts(path: Path) -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    if path.is_file():
        try:
            keys.load(str(path))
        except Exception:
            raise InventoryError(
                f"Cannot parse the SSH known_hosts file at {path}; repair it before enrolling another key."
            ) from None
    return keys


def _append_key(path: Path, host_name: str, key: paramiko.PKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix = b""
    if path.is_file() and path.stat().st_size:
        with path.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) not in {b"\n", b"\r"}:
                prefix = b"\n"
    entry = f"{host_name} {key.get_name()} {key.get_base64()}\n".encode("ascii")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, prefix + entry)
    finally:
        os.close(descriptor)


def prepare_host_key_enrollment(
    inventory: InventoryReader,
    name: str,
    key_fetcher: Callable[[str, int, int], paramiko.PKey] | None = None,
) -> HostKeyEnrollmentProposal:
    """Retrieve and validate a device key without prompting or writing."""
    device = inventory.get(name)
    fetcher = key_fetcher or fetch_host_key
    key = fetcher(device.host, device.port, 10)
    fingerprint = sha256_fingerprint(key)
    host_name = known_hosts_name(device.host, device.port)
    path = Path(env("NERD_KNOWN_HOSTS", "~/.ssh/known_hosts")).expanduser().resolve()
    known = _load_known_hosts(path)
    existing = known.lookup(host_name) or {}
    stored = existing.get(key.get_name())
    if stored is not None:
        if stored.asbytes() == key.asbytes():
            return HostKeyEnrollmentProposal(
                device.name, device.host, device.port, key.get_name(),
                fingerprint, path, "already_enrolled", key,
            )
        raise InventoryError(
            f"SSH host-key conflict for {device.name}. Stored {sha256_fingerprint(stored)}; "
            f"received {fingerprint}. The stored key was not changed. Verify the device and investigate."
        )

    return HostKeyEnrollmentProposal(
        device.name, device.host, device.port, key.get_name(), fingerprint,
        path, "pending", key,
    )


def commit_host_key_enrollment(
    proposal: HostKeyEnrollmentProposal,
) -> dict[str, object]:
    """Append a prepared key while refusing changes that occurred after review."""
    if proposal.status == "already_enrolled":
        return proposal.result()
    known = _load_known_hosts(proposal.known_hosts)
    existing = known.lookup(known_hosts_name(proposal.host, proposal.port)) or {}
    stored = existing.get(proposal.algorithm)
    if stored is not None:
        if stored.asbytes() == proposal.key.asbytes():
            return proposal.result("already_enrolled")
        raise InventoryError(
            f"SSH host-key conflict for {proposal.device}. Stored "
            f"{sha256_fingerprint(stored)}; received {proposal.fingerprint}. "
            "The stored key was not changed. Verify the device and investigate."
        )
    try:
        _append_key(
            proposal.known_hosts,
            known_hosts_name(proposal.host, proposal.port), proposal.key,
        )
    except OSError:
        raise InventoryError(
            f"Could not write the SSH known_hosts file at {proposal.known_hosts}."
        ) from None
    return proposal.result("enrolled")


def enroll_host_key(
    inventory: InventoryReader,
    name: str,
    confirmer: Callable[[str], str] | None = None,
    key_fetcher: Callable[[str, int, int], paramiko.PKey] | None = None,
) -> dict[str, object]:
    """Compatibility facade that retains historical interactive enrollment."""
    proposal = prepare_host_key_enrollment(inventory, name, key_fetcher)
    if proposal.status == "already_enrolled":
        return proposal.result()
    prompt = (
        f"Device: {proposal.device} ({proposal.host}:{proposal.port})\n"
        f"Algorithm: {proposal.algorithm}\n"
        f"SHA-256 fingerprint: {proposal.fingerprint}\n"
        "Verify this fingerprint using the device console or another trusted source.\n"
        "Type yes to enroll this host key: "
    )
    try:
        approved = (confirmer or input)(prompt).strip().casefold() == "yes"
    except EOFError:
        approved = False
    if not approved:
        raise InventoryError(
            "SSH host key was not enrolled; confirmation requires typing yes."
        )
    return commit_host_key_enrollment(proposal)
