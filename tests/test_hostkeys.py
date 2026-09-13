from unittest.mock import Mock

import paramiko
import pytest

from nerd_mcp.cli import main
from nerd_mcp.hostkeys import (
    commit_host_key_enrollment,
    enroll_host_key,
    known_hosts_name,
    prepare_host_key_enrollment,
    sha256_fingerprint,
)
from nerd_mcp.inventory import Inventory, InventoryError


@pytest.fixture
def enrollment(tmp_path, monkeypatch):
    source = tmp_path / "devices.csv"
    source.write_text("name,host,port\nR3,192.0.2.30,2222\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    known_hosts = tmp_path / ".ssh" / "known_hosts"
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    return inventory, known_hosts


def test_enrolls_confirmed_sha256_key(enrollment):
    inventory, known_hosts = enrollment
    key = paramiko.RSAKey.generate(1024)
    prompts = []
    result = enroll_host_key(
        inventory, "R3", lambda prompt: prompts.append(prompt) or "yes",
        lambda host, port, timeout: key,
    )
    assert result["status"] == "enrolled"
    assert result["fingerprint"] == sha256_fingerprint(key)
    assert "SHA-256 fingerprint" in prompts[0]
    assert known_hosts_name("192.0.2.30", 2222) in known_hosts.read_text(encoding="ascii")
    stored = paramiko.HostKeys(str(known_hosts)).lookup("[192.0.2.30]:2222")
    assert stored[key.get_name()].asbytes() == key.asbytes()


def test_declining_enrollment_writes_nothing(enrollment):
    inventory, known_hosts = enrollment
    key = paramiko.RSAKey.generate(1024)
    with pytest.raises(InventoryError, match="typing yes"):
        enroll_host_key(inventory, "R3", lambda prompt: "no", lambda host, port, timeout: key)
    assert not known_hosts.exists()


def test_existing_identical_key_needs_no_confirmation(enrollment):
    inventory, _known_hosts = enrollment
    key = paramiko.RSAKey.generate(1024)
    fetcher = lambda host, port, timeout: key
    enroll_host_key(inventory, "R3", lambda prompt: "yes", fetcher)
    confirmer = Mock(side_effect=AssertionError("should not prompt"))
    result = enroll_host_key(inventory, "R3", confirmer, fetcher)
    assert result["status"] == "already_enrolled"
    confirmer.assert_not_called()


def test_conflicting_key_is_never_overwritten(enrollment):
    inventory, known_hosts = enrollment
    first = paramiko.RSAKey.generate(1024)
    second = paramiko.RSAKey.generate(1024)
    enroll_host_key(inventory, "R3", lambda prompt: "yes", lambda host, port, timeout: first)
    original = known_hosts.read_bytes()
    with pytest.raises(InventoryError, match="host-key conflict") as error:
        enroll_host_key(inventory, "R3", lambda prompt: "yes", lambda host, port, timeout: second)
    assert sha256_fingerprint(first) in str(error.value)
    assert sha256_fingerprint(second) in str(error.value)
    assert known_hosts.read_bytes() == original


def test_unknown_device_never_fetches_a_key(enrollment):
    inventory, _known_hosts = enrollment
    fetcher = Mock()
    with pytest.raises(InventoryError, match="Unknown device"):
        enroll_host_key(inventory, "R3;reload", lambda prompt: "yes", fetcher)
    fetcher.assert_not_called()


def test_cli_host_key_enrollment(enrollment, monkeypatch, capsys):
    inventory, _known_hosts = enrollment
    key = paramiko.RSAKey.generate(1024)
    monkeypatch.setattr("nerd_mcp.hostkeys.fetch_host_key", lambda host, port, timeout: key)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert main([
        "--db", str(inventory.path), "devices", "host-key", "enroll", "R3"
    ]) == 0
    output = capsys.readouterr().out
    assert "Enrolled R3 host key" in output
    assert sha256_fingerprint(key) in output


def test_prepare_does_not_prompt_or_write(enrollment):
    inventory, known_hosts = enrollment
    key = paramiko.RSAKey.generate(1024)
    proposal = prepare_host_key_enrollment(
        inventory, "R3", lambda host, port, timeout: key
    )
    assert proposal.status == "pending"
    assert proposal.fingerprint == sha256_fingerprint(key)
    assert not known_hosts.exists()

    result = commit_host_key_enrollment(proposal)
    assert result["status"] == "enrolled"
    assert known_hosts.exists()
