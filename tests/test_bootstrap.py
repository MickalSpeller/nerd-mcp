from unittest.mock import Mock, patch

import pytest

from nerd_mcp.bootstrap import build_application
from nerd_mcp.inventory import Inventory
from nerd_mcp.server import build_server
from nerd_mcp.ssh_pool import SSHConnectionPool


def make_inventory(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_csv(source)
    return inventory


def test_application_builds_one_shared_service_graph(tmp_path):
    inventory = make_inventory(tmp_path)
    application = build_application(inventory, mock=True)

    assert application.inventory is inventory
    assert application.network._workflow.inventory is inventory
    assert application.network._workflow.transport is application.transport
    assert application.transport.session_factory is application.session_factory
    assert application.inventory_refresh.network is application.network
    assert application.fleet_health.network is application.network
    assert application.routing._workflow.network is application.network
    assert application.routing._workflow.command_reader is application.network
    assert application.routing._workflow.routing_collector is application.routing_evidence
    assert application.routing_evidence.command_reader is application.network
    assert application.baselines._baselines.network is application.network
    assert application.baseline_writes._baselines is application.baselines._baselines
    assert application.baseline_writes.inventory is application.inventory
    assert not hasattr(application.baselines, "capture")
    assert not hasattr(application.baselines, "remove")
    assert application.topology._workflow.mac_service is application.mac
    assert application.topology._presenter.__class__.__name__ == "TopologyDiagramPresenter"
    assert application.mac._workflow.transport is application.transport
    assert application.mac._workflow.index is application.observations
    assert application.topology._workflow.index is application.observations
    assert application.baselines._baselines.repository is application.baseline_repository
    assert application.mac_paths._workflow.mac_service is application.mac
    assert application.mac_paths._workflow.topology_service is application.topology
    assert application.endpoints._workflow.mac_service is application.mac
    assert application.endpoints._workflow.path_service is application.mac_paths
    assert application.ssh_pool is None


def test_short_lived_graph_does_not_create_or_use_a_pool(tmp_path):
    connector = Mock(side_effect=AssertionError("SSH must not be used while bootstrapping"))
    with patch("nerd_mcp.bootstrap.SSHConnectionPool") as pool_type:
        application = build_application(
            make_inventory(tmp_path), mock=True, connector=connector
        )
    pool_type.assert_not_called()
    connector.assert_not_called()
    application.close()


def test_pooled_graph_shares_one_pool_and_closes_once_on_exception(tmp_path):
    connector = Mock(side_effect=AssertionError("SSH must not be used while bootstrapping"))
    application = build_application(
        make_inventory(tmp_path), mock=True, pooled=True, connector=connector
    )
    close_all = Mock(wraps=application.ssh_pool.close_all)
    application.ssh_pool.close_all = close_all

    assert application.transport.connection_pool is application.ssh_pool
    assert application.ssh_pool.session_factory is application.session_factory
    assert application.network._workflow.transport is application.transport
    assert application.mac._workflow.transport is application.transport
    assert application.routing._workflow.network is application.network
    connector.assert_not_called()

    with pytest.raises(RuntimeError, match="adapter stopped"):
        with application:
            raise RuntimeError("adapter stopped")
    application.close()
    close_all.assert_called_once_with()


def test_application_context_closes_pool_after_normal_exit(tmp_path):
    application = build_application(make_inventory(tmp_path), mock=True, pooled=True)
    close_all = Mock(wraps=application.ssh_pool.close_all)
    application.ssh_pool.close_all = close_all

    with application as entered:
        assert entered is application
    application.close()
    close_all.assert_called_once_with()


@pytest.mark.asyncio
async def test_mcp_lifespan_closes_its_application_once(tmp_path):
    application = build_application(make_inventory(tmp_path), mock=True, pooled=True)
    close_all = Mock(wraps=application.ssh_pool.close_all)
    application.ssh_pool.close_all = close_all
    server = build_server(application=application)

    with pytest.raises(RuntimeError, match="server stopped"):
        async with server._mcp_server.lifespan(server._mcp_server):
            raise RuntimeError("server stopped")
    application.close()
    close_all.assert_called_once_with()


def test_bootstrap_pool_relies_on_explicit_lifecycle(tmp_path):
    with patch("nerd_mcp.ssh_pool.atexit.register") as register:
        application = build_application(make_inventory(tmp_path), mock=True, pooled=True)
    register.assert_not_called()
    application.close()


def test_standalone_pool_retains_process_exit_fallback():
    with patch("nerd_mcp.ssh_pool.atexit.register") as register:
        pool = SSHConnectionPool()
    register.assert_called_once_with(pool.close_all)
    pool.close_all()
