from unittest.mock import Mock
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from nerd_mcp.inventory import Device, Inventory
from nerd_mcp.network import Network
from nerd_mcp.ssh_pool import SSHConnectionPool


def configure_credentials(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("host key", encoding="utf-8")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda profile: None)


def test_pool_reuses_live_session_and_closes_it(tmp_path, monkeypatch):
    configure_credentials(tmp_path, monkeypatch)
    connection = Mock()
    connection.is_alive.return_value = True
    connector = Mock(return_value=connection)
    pool = SSHConnectionPool(connector=connector, idle_ttl_seconds=60)
    device = Device("R1", "192.0.2.1")
    with pool.connection(device, "cisco_ios") as (first, password):
        assert first is connection and password == "secret"  # pragma: allowlist secret
    with pool.connection(device, "cisco_ios") as (second, _password):
        assert second is connection
    assert connector.call_count == 1
    assert pool.stats() == {
        "active_sessions": 0, "idle_sessions": 1, "created": 1,
        "reused": 1, "expired": 0, "invalidated": 0,
    }
    connection.disconnect.assert_not_called()
    pool.close_all()
    connection.disconnect.assert_called_once()


def test_pool_expires_idle_and_replaces_dead_sessions(tmp_path, monkeypatch):
    configure_credentials(tmp_path, monkeypatch)
    now = [10.0]
    sessions = [Mock(), Mock(), Mock()]
    for session in sessions:
        session.is_alive.return_value = True
    connector = Mock(side_effect=sessions)
    pool = SSHConnectionPool(
        connector=connector, idle_ttl_seconds=5, clock=lambda: now[0]
    )
    device = Device("R1", "192.0.2.1")
    with pool.connection(device, "cisco_ios"):
        pass
    now[0] = 16.0
    with pool.connection(device, "cisco_ios") as (second, _password):
        assert second is sessions[1]
    sessions[1].is_alive.return_value = False
    with pool.connection(device, "cisco_ios") as (third, _password):
        assert third is sessions[2]
    assert connector.call_count == 3
    assert sessions[0].disconnect.call_count == 1
    assert sessions[1].disconnect.call_count == 1
    pool.close_all()


def test_pool_invalidates_session_after_command_exception(tmp_path, monkeypatch):
    configure_credentials(tmp_path, monkeypatch)
    first, second = Mock(), Mock()
    first.is_alive.return_value = second.is_alive.return_value = True
    pool = SSHConnectionPool(connector=Mock(side_effect=[first, second]))
    device = Device("R1", "192.0.2.1")
    with pytest.raises(RuntimeError, match="transport failed"):
        with pool.connection(device, "cisco_ios"):
            raise RuntimeError("transport failed")
    first.disconnect.assert_called_once()
    with pool.connection(device, "cisco_ios") as (connection, _password):
        assert connection is second
    assert pool.stats()["invalidated"] == 1
    pool.close_all()


def test_network_instances_share_one_pooled_login(tmp_path, monkeypatch):
    configure_credentials(tmp_path, monkeypatch)
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text("name,host\nR1,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(csv_path)
    connection = Mock()
    connection.is_alive.return_value = True
    connection.send_command.return_value = "Cisco IOS XE Software, Version 17.9"
    connector = Mock(return_value=connection)
    pool = SSHConnectionPool(connector=connector)
    assert Network(inventory, connection_pool=pool).inspect("get_device_info", "R1")["status"] == "success"
    assert Network(inventory, connection_pool=pool).inspect("get_interfaces", "R1")["status"] == "success"
    assert connector.call_count == 1
    assert connection.send_command.call_count == 2
    pool.close_all()


def test_pool_connects_different_devices_in_parallel(tmp_path, monkeypatch):
    configure_credentials(tmp_path, monkeypatch)
    barrier = Barrier(2)

    def connect(**_kwargs):
        barrier.wait(timeout=2)
        session = Mock()
        session.is_alive.return_value = True
        return session

    pool = SSHConnectionPool(connector=connect)
    devices = [Device("R1", "192.0.2.1"), Device("R2", "192.0.2.2")]

    def acquire(device):
        with pool.connection(device, "cisco_ios") as (session, _password):
            return session

    with ThreadPoolExecutor(max_workers=2) as workers:
        sessions = list(workers.map(acquire, devices))
    assert len(sessions) == 2 and sessions[0] is not sessions[1]
    assert pool.stats()["created"] == 2
    pool.close_all()
