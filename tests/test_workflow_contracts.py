"""Characterization of the terminal workflows and existing MCP catalog."""
import asyncio
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import re
import sqlite3
from unittest.mock import patch

import pytest

from nerd_mcp.cli import main
from nerd_mcp.application.inspection import NetworkWorkflow
from nerd_mcp.execution import ExecutionTrace
from nerd_mcp.inventory import Inventory
from nerd_mcp.server import build_server


def capture_contracts(root):
    inventory = Inventory(root / "inventory.db")
    source = root / "synthetic.csv"
    source.write_text("name,host,location\nbeta,192.0.2.2,Operator location\nalpha,192.0.2.1,\n")
    inventory.import_csv(source)
    empty = Inventory(root / "empty.db")
    cases = {
        "refresh_single": (inventory, ["devices", "refresh", "alpha", "--mock"]),
        "refresh_all": (inventory, ["devices", "refresh", "ALL", "--mock"]),
        "refresh_unknown": (inventory, ["devices", "refresh", "missing", "--mock"]),
        "refresh_empty": (empty, ["devices", "refresh", "all", "--mock"]),
        "health_json": (inventory, ["health", "ALL", "--mock", "--json"]),
        "health_terminal": (inventory, ["health", "alpha", "--mock"]),
        "health_unknown": (inventory, ["health", "missing", "--mock", "--json"]),
        "health_empty": (empty, ["health", "all", "--mock"]),
        "health_no_footer": (inventory, ["--no-footer", "health", "alpha", "--mock", "--json"]),
    }
    captured = {}
    with patch("logging.basicConfig"), patch("nerd_mcp.cli.ExecutionTrace", lambda: ExecutionTrace(started_at=0, finished_at=1)), patch.dict(
        "os.environ", {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"}
    ), patch(
        "nerd_mcp.transport.netmiko.NetmikoSessionFactory.connect",
        side_effect=AssertionError("Mock must not connect"),
    ):
        for key, (db, args) in cases.items():
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["--db", str(db.path), *args])
            captured[key] = {
                "exit_code": code,
                "stdout": re.sub(r"\d{4}-\d{2}-\d{2}T[0-9:.+Z-]+", "<timestamp>", out.getvalue()),
                "stderr": err.getvalue(),
            }
        with patch.object(Inventory, "update_facts", side_effect=sqlite3.OperationalError("write failed")):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["--db", str(inventory.path), "devices", "refresh", "alpha", "--mock"])
            captured["refresh_write_failure"] = {"exit_code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}
    assert inventory.get("beta").location == "Operator location"
    server = build_server(inventory, mock=True)
    captured["mcp_tools"] = [tool.model_dump(mode="json") for tool in asyncio.run(server.list_tools())]
    return captured


def test_workflow_and_mcp_contracts(tmp_path):
    expected = json.loads((Path(__file__).parent / "fixtures" / "workflow_contracts.json").read_text())
    actual = capture_contracts(tmp_path)
    for key in expected:
        if key == 'mcp_tools':
            assert actual[key] == expected[key]
        else:
            for field in expected[key]:
                assert actual[key][field] == expected[key][field], (key, field)


@pytest.mark.parametrize("results, expected", [
    ([{"status": "success", "overall": "healthy"}], 0),
    ([{"status": "success", "overall": "warning"}], 0),
    ([{"status": "success", "overall": "critical"}], 2),
    ([{"status": "success", "overall": "critical"}, {"status": "error"}], 1),
])
def test_health_exit_precedence(tmp_path, capsys, results, expected):
    inventory = Inventory(tmp_path / "inventory.db")
    source = tmp_path / "synthetic.csv"
    source.write_text("name,host\n" + "".join(f"d{i},192.0.2.{i+1}\n" for i in range(len(results))))
    inventory.import_csv(source)
    with patch.object(NetworkWorkflow, "health", side_effect=results) as health:
        assert main(["--db", str(inventory.path), "--no-footer", "health", "ALL", "--json", "--mock"]) == expected
    assert json.loads(capsys.readouterr().out) == results
    assert [call.args[0] for call in health.call_args_list] == [f"d{i}" for i in range(len(results))]


def test_refresh_keeps_failures_and_persists_successes(tmp_path, capsys):
    inventory = Inventory(tmp_path / "inventory.db")
    source = tmp_path / "synthetic.csv"
    source.write_text("name,host\na,192.0.2.1\nb,192.0.2.2\nc,192.0.2.3\n")
    inventory.import_csv(source)
    responses = [{"status": "success", "facts": {"model": "first"}},
                 {"status": "error", "error": "unavailable"},
                 {"status": "success", "facts": {"model": "last"}}]
    with patch.object(NetworkWorkflow, "discover_inventory", side_effect=responses) as discover:
        assert main(["--db", str(inventory.path), "--no-footer", "devices", "refresh", "ALL", "--mock"]) == 1
    results = json.loads(capsys.readouterr().out)
    assert results[1] == responses[1]
    assert results[0]["record"]["model"] == "first"
    assert results[2]["record"]["model"] == "last"
    assert inventory.get("b").model == ""
    assert [call.args[0] for call in discover.call_args_list] == ["a", "b", "c"]
