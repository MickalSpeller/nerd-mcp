"""SSH lifecycle and policy checks use fake connectors only."""
from unittest.mock import Mock, call

import pytest
from netmiko.exceptions import ReadTimeout, NetmikoAuthenticationException

from nerd_mcp.inventory import Inventory, InventoryError
from nerd_mcp.mac import MacService, adapter_for
from nerd_mcp.network import Network
from nerd_mcp.ssh_pool import SSHConnectionPool
from nerd_mcp.transport.netmiko import NetmikoSessionFactory, NetmikoTransport


@pytest.fixture
def configured(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic host keys")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "synthetic-secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda _: None)
    source = tmp_path / "synthetic.csv"
    source.write_text("name,host,port\ncore,192.0.2.1,2222\n")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(source)
    return inventory, inventory.get("core"), known_hosts


@pytest.mark.parametrize("pooled, timeout", [(False, 30), (False, 90), (True, 30), (True, 90)])
def test_verified_options_and_session_ownership(configured, pooled, timeout):
    _, device, known_hosts = configured
    session = Mock()
    connector = Mock(return_value=session)
    pool = SSHConnectionPool(connector=connector) if pooled else None
    transport = NetmikoTransport(connector, pool)
    try:
        with transport.connection(device, "cisco_ios", timeout) as (connection, password):
            assert connection is session and password == "synthetic-secret"  # pragma: allowlist secret
        effective = max(60, timeout) if pooled else timeout
        connector.assert_called_once_with(
            device_type="cisco_ios", host="192.0.2.1", port=2222,
            username="operator", password="synthetic-secret", ssh_strict=True,  # pragma: allowlist secret
            system_host_keys=False, alt_host_keys=True, alt_key_file=str(known_hosts),
            use_keys=False, allow_agent=False, conn_timeout=10, auth_timeout=10,
            banner_timeout=10, blocking_timeout=15, timeout=effective,
            read_timeout_override=effective, session_log=None,
        )
        assert session.disconnect.call_count == (0 if pooled else 1)
    finally:
        if pool:
            pool.close_all()
    session.disconnect.assert_called_once()


@pytest.mark.parametrize("pooled", [False, True])
def test_missing_trust_prevents_connect(configured, monkeypatch, pooled):
    _, device, known_hosts = configured
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts.parent / "missing"))
    connector = Mock()
    pool = SSHConnectionPool(connector=connector) if pooled else None
    try:
        with pytest.raises(InventoryError, match="known_hosts file missing"):
            with NetmikoTransport(connector, pool).connection(device, "cisco_ios"):
                pytest.fail("must not yield")
        connector.assert_not_called()
        if pool:
            assert pool.stats()["active_sessions"] == 0
    finally:
        if pool:
            pool.close_all()


def test_legacy_settings_and_credentials(configured, monkeypatch):
    _, device, known_hosts = configured
    for suffix in ("KNOWN_HOSTS", "DEFAULT_USERNAME", "DEFAULT_PASSWORD"):
        monkeypatch.delenv("NERD_" + suffix)
    monkeypatch.setenv("CISCO_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("CISCO_DEFAULT_USERNAME", "legacy-user")
    monkeypatch.setenv("CISCO_DEFAULT_PASSWORD", "legacy-secret")  # pragma: allowlist secret
    connector = Mock()
    with NetmikoTransport(connector).connection(device, "cisco_ios") as (_, password):
        assert password == "legacy-secret"  # pragma: allowlist secret
    assert connector.call_args.kwargs["username"] == "legacy-user"
    assert connector.call_args.kwargs["alt_key_file"] == str(known_hosts)


def test_cleanup_failure_keeps_original_error_and_does_not_log_secrets(configured, caplog):
    import logging
    _, device, _ = configured
    session = Mock()
    session.disconnect.side_effect = RuntimeError("synthetic-secret")
    failure = ReadTimeout("original failure")
    session.send_command.side_effect = failure
    connector = Mock(return_value=session)
    transport = NetmikoTransport(connector, logger=logging.getLogger("nerd_mcp.transport.test"))
    with pytest.raises(ReadTimeout) as caught:
        transport.read_many(device, "cisco_ios", {"a": "show version"}, 30,
                            retry_pooled_timeout=True)
    assert caught.value is failure
    connector.assert_called_once()
    session.disconnect.assert_called_once()
    assert "SSH cleanup failed" in caplog.text
    assert "synthetic-secret" not in caplog.text


def test_pooled_retry_restarts_batch_and_invalidates_failed_session(configured):
    _, device, _ = configured
    first, second = Mock(), Mock()
    first.send_command.side_effect = ["partial", ReadTimeout("failure")]
    second.send_command.side_effect = ["first", "second"]
    connector = Mock(side_effect=[first, second])
    pool = SSHConnectionPool(connector=connector)
    try:
        output, _ = NetmikoTransport(connection_pool=pool).read_many(
            device, "cisco_ios", {"a": "show version", "b": "show interfaces"}, 30,
            retry_pooled_timeout=True,
        )
        assert output == {"a": "first", "b": "second"}
        assert first.send_command.call_args_list == second.send_command.call_args_list
        first.disconnect.assert_called_once()
        assert pool.stats()["invalidated"] == 1
    finally:
        pool.close_all()


@pytest.mark.parametrize("error", [ReadTimeout("unavailable"), NetmikoAuthenticationException("unavailable")])
def test_mac_pooled_reads_do_not_retry(configured, error):
    inventory, device, _ = configured
    session = Mock()
    session.send_command.side_effect = error
    connector = Mock(return_value=session)
    pool = SSHConnectionPool(connector=connector)
    try:
        with pytest.raises(type(error)):
            MacService(inventory, connection_pool=pool)._run_commands(device, adapter_for(device))
        connector.assert_called_once()
        session.disconnect.assert_called_once()
    finally:
        pool.close_all()


def test_mac_short_session_preserves_fallback_redaction_and_cleanup(configured):
    inventory, device, _ = configured
    session = Mock()
    session.send_command.side_effect = ["% Invalid input", "synthetic-secret output"]
    connector = Mock(return_value=session)
    # Exercise the existing fallback sequence with a bounded synthetic adapter.
    adapter = Mock(family="cisco", netmiko_type="cisco_ios", commands={"mac": ("show mac address-table", "show mac-address-table")})
    outputs, used = MacService(inventory, connector=connector)._run_commands(device, adapter)
    assert outputs == {"mac": "[REDACTED] output"}
    assert used == ["show mac address-table", "show mac-address-table"]
    assert session.send_command.call_args_list == [call(command, read_timeout=60) for command in used]
    session.disconnect.assert_called_once()


def test_mock_services_bypass_transport_and_credentials(configured, monkeypatch):
    inventory, device, _ = configured
    forbidden = Mock(side_effect=AssertionError("mock reached SSH"))
    monkeypatch.setattr(NetmikoTransport, "connection", forbidden)
    monkeypatch.setattr("nerd_mcp.transport.netmiko.resolve_credentials", forbidden)
    assert Network(inventory, mock=True).inspect("get_interfaces", "core")["status"] == "success"
    MacService(inventory, mock=True)._run_commands(device, adapter_for(device))
    forbidden.assert_not_called()


def test_connect_failure_is_not_retried_and_pool_recovers(configured):
    _, device, _ = configured
    session = Mock()
    connector = Mock(side_effect=[NetmikoAuthenticationException("failure"), session])
    pool = SSHConnectionPool(connector=connector)
    try:
        transport = NetmikoTransport(connection_pool=pool)
        with pytest.raises(NetmikoAuthenticationException):
            transport.read_many(device, "cisco_ios", {"a": "show version"}, 30,
                                retry_pooled_timeout=True)
        assert connector.call_count == 1
        assert pool.stats()["active_sessions"] == 0
        with transport.connection(device, "cisco_ios"):
            pass
        assert connector.call_count == 2
    finally:
        pool.close_all()


def test_pool_reconnects_when_resolved_credentials_change(configured):
    _, device, known_hosts = configured
    credentials = ["first-secret"]
    first, second = Mock(), Mock()
    first.is_alive.return_value = second.is_alive.return_value = True
    connector = Mock(side_effect=[first, second])
    session_factory = NetmikoSessionFactory(
        connector=connector,
        credential_resolver=lambda _profile: (
            "operator", credentials[0], "synthetic"
        ),
        known_hosts_resolver=lambda: known_hosts,
    )
    pool = SSHConnectionPool(session_factory=session_factory)
    try:
        with pool.connection(device, "cisco_ios"):
            pass
        credentials[0] = "second-secret"
        with pool.connection(device, "cisco_ios"):
            pass
        assert [call.kwargs["password"] for call in connector.call_args_list] == [
            "first-secret", "second-secret"
        ]
        first.disconnect.assert_called_once()
        assert pool.stats()["invalidated"] == 1
    finally:
        pool.close_all()
