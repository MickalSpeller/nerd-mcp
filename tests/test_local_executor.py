import json
import subprocess
import sys
import tomllib
from pathlib import Path

from nerd_mcp.application.operations import operation_names
from nerd_mcp.bootstrap import build_application
from nerd_mcp.chat import Chat
from nerd_mcp.inventory import Inventory
from nerd_mcp.local_executor import LocalExecutor


def make_application(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return build_application(inventory, mock=True, pooled=True)


async def test_local_executor_matches_recorded_mcp_names_and_schemas(tmp_path):
    application = make_application(tmp_path)
    try:
        local = (await LocalExecutor(application).list_tools()).tools
        recorded = json.loads(
            (Path(__file__).parent / "fixtures" / "workflow_contracts.json")
            .read_text(encoding="utf-8")
        )["mcp_tools"]
        expected = {tool["name"]: tool["inputSchema"] for tool in recorded}
        actual = {tool.name: tool.inputSchema for tool in local}
        assert set(actual) == operation_names(mcp_only=True)
        assert actual == expected
    finally:
        application.close()


async def test_local_executor_runs_inventory_and_mock_device_operations(tmp_path):
    application = make_application(tmp_path)
    executor = LocalExecutor(application)
    try:
        devices = await executor.call_tool("list_devices", {})
        assert not devices.isError
        assert devices.structuredContent["devices"][0]["name"] == "core"

        ospf = await executor.call_tool("get_ospf_status", {"device": "core"})
        assert not ospf.isError
        assert ospf.structuredContent["status"] == "success"
        assert ospf.structuredContent["neighbor_count"] == 1

        configuration = await executor.call_tool("get_configuration", {
            "device": "core", "source": "running", "cursor": 0, "revision": "",
        })
        assert not configuration.isError
        assert configuration.structuredContent["complete"] is True
        assert "mock-enable-secret" not in configuration.structuredContent["output"]
    finally:
        application.close()


async def test_local_executor_maps_topology_format_to_application_argument(tmp_path):
    application = make_application(tmp_path)
    executor = LocalExecutor(application)
    try:
        result = await executor.call_tool("get_topology_diagram", {
            "target": "all", "location": "", "max_age_minutes": 60,
            "format": "mermaid",
        })
        assert not result.isError
        assert result.structuredContent["format"] == "mermaid"
        assert result.structuredContent["diagram"].startswith("flowchart LR\n")
    finally:
        application.close()


async def test_chat_accepts_local_executor_without_mcp_session(tmp_path):
    application = make_application(tmp_path)
    executor = LocalExecutor(application)
    try:
        tools = (await executor.list_tools()).tools
        chat = Chat(None, executor, "unused-model", tools, mock=True)
        output = await chat.execute_named("list_devices", {})
        assert output["status"] == "success"
        assert output["result"]["devices"][0]["name"] == "core"
    finally:
        application.close()


async def test_local_executor_rejects_invalid_or_unknown_calls(tmp_path):
    application = make_application(tmp_path)
    executor = LocalExecutor(application)
    try:
        invalid = await executor.call_tool("get_health", {"device": "core", "extra": True})
        unknown = await executor.call_tool("not_a_tool", {})
        assert invalid.isError and invalid.structuredContent == {"error": "Invalid tool arguments."}
        assert unknown.isError and unknown.structuredContent == {"error": "Unknown tool."}
    finally:
        application.close()


def test_deterministic_cli_runs_without_openai_or_mcp(tmp_path):
    code = r'''
import importlib.abc
import sys

class BlockOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp" or fullname.startswith("mcp.") or fullname == "openai" or fullname.startswith("openai."):
            raise ModuleNotFoundError(fullname)
        return None

sys.meta_path.insert(0, BlockOptional())
import nerd_mcp.cli
import nerd_mcp.chat
import nerd_mcp.local_executor
assert nerd_mcp.cli.main([
    "--no-footer", "--db", sys.argv[1], "devices", "list"
]) == 0
print("optional imports isolated")
'''
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "isolated.db")],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "optional imports isolated" in result.stdout


def test_openai_and_mcp_are_explicit_package_extras():
    metadata = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    dependencies = " ".join(metadata["dependencies"]).casefold()
    assert "openai" not in dependencies
    assert "mcp" not in dependencies
    assert metadata["optional-dependencies"]["chat"] == ["openai==3.8.0"]
    assert metadata["optional-dependencies"]["mcp"] == ["mcp==1.30.0"]
