import json
import io
from contextlib import asynccontextmanager

from rich.console import Console

from nerd_mcp.cli import main
from nerd_mcp.execution import ExecutionTrace
from nerd_mcp.inventory import Inventory
from nerd_mcp.presentation import (
    BANNER_COLOR,
    CONFIG_COLOR,
    CONFIG_ADDED_COLOR,
    CONFIG_REMOVED_COLOR,
    NERD_BANNER,
    PRIMARY_COLOR,
    PROMPT_COLOR,
    header,
    read_prompt,
    render_answer,
    render_configuration,
    render_execution,
    render_diagnosis,
)


def inventory_path(tmp_path):
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    db_path = tmp_path / "devices.db"
    Inventory(db_path).import_csv(csv_path)
    return db_path


def fortios_inventory_path(tmp_path):
    csv_path = tmp_path / "fortios.csv"
    csv_path.write_text(
        "name,host,device_type,vendor,platform\n"
        "FW01,192.0.2.10,firewall,Fortinet,FortiOS\n",
        encoding="utf-8",
    )
    db_path = tmp_path / "fortios.db"
    Inventory(db_path).import_csv(csv_path)
    return db_path


def test_chat_can_select_mcp_compatibility_transport(tmp_path, monkeypatch):
    db_path = inventory_path(tmp_path)
    marker = object()
    calls = {}

    @asynccontextmanager
    async def fake_session(path, mock=False):
        calls["session"] = (path, mock)
        yield marker

    async def fake_run_chat(path, mock=False, show_footer=True, **options):
        calls["chat"] = (path, mock, show_footer, options)

    monkeypatch.setattr("nerd_mcp.chat.local_session", fake_session)
    monkeypatch.setattr("nerd_mcp.chat.run_chat", fake_run_chat)

    assert main([
        "--no-footer", "--db", str(db_path), "chat", "--mock",
        "--tool-transport", "mcp",
    ]) == 0
    assert calls["session"] == (db_path.resolve(), True)
    assert calls["chat"][3]["executor"] is marker
    assert calls["chat"][3]["application"].inventory.path == db_path.resolve()
    assert calls["chat"][3]["write_enabled"] is False


def test_chat_requires_explicit_write_opt_in(tmp_path, monkeypatch):
    db_path = inventory_path(tmp_path)
    calls = {}

    async def fake_run_chat(path, mock=False, show_footer=True, **options):
        calls.update(options)

    monkeypatch.setattr("nerd_mcp.chat.run_chat", fake_run_chat)
    assert main([
        "--no-footer", "--db", str(db_path), "chat", "--mock", "--enable-writes",
    ]) == 0
    assert calls["write_enabled"] is True


def test_change_execution_is_blocked_without_write_opt_in(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "change", "apply", "CHG-000000000000",
    ]) == 1
    assert "disabled by default" in capsys.readouterr().err


def test_config_cli_prints_complete_sanitized_config(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main(["--db", str(db_path), "config", "core", "--mock"]) == 0
    captured = capsys.readouterr()
    assert "hostname mock-device" in captured.out
    assert "mock-enable-secret" not in captured.out
    assert "secret-bearing line" in captured.err


def test_config_cli_writes_only_sanitized_config(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    output_path = tmp_path / "core-startup.txt"
    assert main([
        "--db", str(db_path), "config", "core", "--source", "startup",
        "--output", str(output_path), "--mock",
    ]) == 0
    saved = output_path.read_text(encoding="utf-8")
    assert "hostname mock-device" in saved
    assert "mock-community" not in saved
    assert "Saved sanitized startup configuration" in capsys.readouterr().out


def test_inspect_cli_exposes_paginated_configuration(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--db", str(db_path), "inspect", "core", "get_configuration", "--mock"
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "success"
    assert result["source"] == "running"
    assert result["complete"] is True
    assert result["cursor"] == 0


def test_inspect_cli_exposes_ospf_status(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--db", str(db_path), "inspect", "core", "get_ospf_status", "--mock"
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "success"
    assert result["running"] is True
    assert result["processes"][0]["process_id"] == "1"
    assert result["neighbors"][0]["state"] == "FULL/DR"


def test_vpn_cli_renders_and_serializes_fortios_status(tmp_path, capsys):
    db_path = fortios_inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "vpn", "status", "FW01", "--mock",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "VPN Status: FW01" in rendered
    assert "Branch-HQ" in rendered
    assert "1 active session" in rendered

    assert main([
        "--no-footer", "--db", str(db_path), "vpn", "status", "FW01",
        "--mock", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["complete"] and result["has_active_vpn"]
    assert result["ipsec"]["active_count"] == 1

    assert main([
        "--no-footer", "--db", str(db_path), "inspect", "FW01",
        "get_vpn_status", "--mock",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["ssl_vpn"]["active_session_count"] == 1


def test_snapshot_cli_create_list_show_compare_and_remove(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    prefix = ["--no-footer", "--db", str(db_path), "snapshot"]
    assert main([*prefix, "create", "core", "--mock", "--json"]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["baseline"]["device"] == "core"
    assert main([*prefix, "create", "core", "--mock"]) == 1
    assert "--replace" in capsys.readouterr().err
    assert main([*prefix, "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1
    output_path = tmp_path / "baseline.txt"
    assert main([*prefix, "show", "core", "--output", str(output_path)]) == 0
    assert "mock-enable-secret" not in output_path.read_text(encoding="utf-8")
    capsys.readouterr()
    assert main([*prefix, "compare", "core", "--mock", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False
    assert main([*prefix, "compare", "all", "--workers", "2", "--mock", "--json"]) == 0
    fleet = json.loads(capsys.readouterr().out)
    assert fleet["counts"]["unchanged"] == 1
    assert "diff" not in fleet["results"][0]
    assert main([*prefix, "compare", "all", "--workers", "2", "--mock"]) == 0
    assert "Fleet Configuration Drift" in capsys.readouterr().out
    assert main(["--no-footer", "--db", str(db_path), "snapshot", "status", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["devices"][0]["last_status"] == "unchanged"
    assert status["devices"][0]["age_days"] == 0
    assert main(["--no-footer", "--db", str(db_path), "snapshot", "status"]) == 0
    assert "Configuration Baseline Status" in capsys.readouterr().out
    assert main([*prefix, "remove", "core"]) == 0
    assert "Removed configuration baseline" in capsys.readouterr().out


def test_snapshot_cli_creates_all_missing_baselines_without_bulk_replace(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    prefix = ["--no-footer", "--db", str(db_path), "snapshot", "create", "all"]
    assert main([*prefix, "--workers", "2", "--mock", "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["counts"]["created"] == 1
    assert main([*prefix, "--workers", "2", "--mock"]) == 0
    assert "Fleet Baseline Creation" in capsys.readouterr().out
    assert main([*prefix, "--replace", "--mock"]) == 1
    assert "Bulk baseline replacement is not allowed" in capsys.readouterr().err


def test_snapshot_cli_refresh_all_requires_confirmation_and_reports_results(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    base = ["--no-footer", "--db", str(db_path), "snapshot"]
    assert main([*base, "create", "core", "--mock", "--json"]) == 0
    capsys.readouterr()
    assert main([*base, "refresh", "all", "--mock", "--json"]) == 1
    assert "requires --yes" in capsys.readouterr().err
    assert main([*base, "refresh", "all", "--workers", "2", "--mock", "--yes", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"] == {"total": 1, "refreshed": 1, "created": 0, "failed": 0}
    assert main([*base, "refresh", "all", "--mock", "--yes"]) == 0
    assert "Fleet Baseline Refresh" in capsys.readouterr().out


def test_chat_uses_nerd_v2_banner_and_color_scheme():
    output = io.StringIO()
    header(Console(file=output, width=120, color_system=None))
    text = output.getvalue()
    assert "███╗   ██╗" in NERD_BANNER
    assert "███╗   ██╗" in text
    assert "Network Engineering Reconnaissance & Discovery" in text
    assert "Vendor-agnostic network reconnaissance and discovery" not in text
    assert "Device output is sent to OpenAI for interpretation" not in text
    assert PRIMARY_COLOR == "#00D7FF"
    assert BANNER_COLOR == "#00D9FF"
    assert PROMPT_COLOR == "green"


def test_chat_uses_exact_nerd_v2_prompt(monkeypatch):
    console = Console(file=io.StringIO())
    prompts = []
    monkeypatch.setattr(console, "input", lambda prompt: prompts.append(prompt) or "devices")
    assert read_prompt(console) == "devices"
    assert "Ask N.E.R.D. › " in prompts[0]
    assert "green" in prompts[0]


def test_chat_answer_renders_markdown_sections_and_removes_copy_padding():
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)
    render_answer(
        console,
        "## Interface Summary\n\nInterfaces&#x20;\n\n- **Up:** Gi0/0&nbsp;\n- **Down:** Gi0/1\n",
    )
    text = output.getvalue()
    lines = text.splitlines()
    assert "Interface Summary" in text
    assert "Interfaces" in text
    assert "Up:" in text and "Gi0/0" in text
    assert "Down:" in text and "Gi0/1" in text
    assert "&#x20;" not in text and "&nbsp;" not in text
    assert all(line == line.rstrip() for line in lines)


def test_configuration_uses_complementary_color_without_changing_text():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_configuration(console, "hostname R1\ninterface Ethernet0/0")
    rendered = output.getvalue()
    assert CONFIG_COLOR == "#FFD166"
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "hostname R1" in rendered
    assert "interface Ethernet0/0" in rendered

    plain = io.StringIO()
    render_configuration(Console(file=plain, color_system=None), "hostname R1")
    assert plain.getvalue() == "hostname R1\n"


def test_configuration_diff_uses_distinct_added_and_removed_colors():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_configuration(
        console,
        "  interface Ethernet0/1\n- description Old uplink\n+ description Branch uplink",
    )
    rendered = output.getvalue()
    assert CONFIG_ADDED_COLOR == "#7EE787"
    assert CONFIG_REMOVED_COLOR == "#FF7B72"
    assert "\x1b[38;2;126;231;135m" in rendered
    assert "\x1b[38;2;255;123;114m" in rendered
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "- description Old uplink" in rendered
    assert "+ description Branch uplink" in rendered

    plain = io.StringIO()
    render_configuration(
        Console(file=plain, color_system=None),
        "- description Old uplink\n+ description Branch uplink",
    )
    assert plain.getvalue() == (
        "- description Old uplink\n+ description Branch uplink\n"
    )


def test_diagnosis_separates_incorrect_live_configuration_from_recommended_diff():
    output = io.StringIO()
    console = Console(file=output, color_system=None, width=120)
    render_diagnosis(console, {
        "diagnosis_id": "DIA-TEST", "state": "prepared",
        "root_cause": {
            "summary": "The peer uses the wrong remote AS.", "confidence": "high",
            "evidence": ["The live neighbor statement specifies AS 65002."],
            "incorrect_configuration": [{
                "device": "R1", "lines": ["neighbor 2.2.2.2 remote-as 65002"],
            }],
        },
        "recommendation": {"summary": "Use AS 65001.", "next_steps": []},
        "plan": {
            "change_id": "CHG-TEST", "state": "prepared", "revision": "a" * 64,
            "request": {"summary": "Correct the BGP peer."},
            "devices": [{
                "device": "R1", "platform": "cisco_ios", "impact": ["BGP neighbor"],
                "configuration_diff": [
                    "  router bgp 65001",
                    "- neighbor 2.2.2.2 remote-as 65002",
                    "+ neighbor 2.2.2.2 remote-as 65001",
                ],
                "verification": [], "save_commands": ["write memory"],
            }, {
                "device": "R2", "platform": "cisco_ios", "impact": [],
                "configuration_diff": [], "verification": [],
                "save_commands": ["write memory"], "already_applied": True,
            }],
        },
    })
    rendered = output.getvalue()
    assert "INCORRECT LIVE CONFIGURATION" in rendered
    assert "  - neighbor 2.2.2.2 remote-as 65002" in rendered
    assert "PROPOSED CONFIGURATION DIFF" in rendered
    assert "+ neighbor 2.2.2.2 remote-as 65001" in rendered
    assert "Recovery:" not in rendered
    assert "Persistence after separate SAVE approval:" not in rendered
    assert "R2 (cisco_ios):" not in rendered
    assert "Already correct: R2" in rendered


def test_chat_ios_blocks_use_configuration_amber():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_answer(
        console,
        "To shut the interface down:\n\n```ios\nconfigure terminal\ninterface Ethernet0/1.15\n shutdown\nend\n```\n\nNo change was made.",
    )
    rendered = output.getvalue()
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "configure terminal" in rendered
    assert "interface Ethernet0/1.15" in rendered
    assert "No change was made." in rendered


def test_chat_recovers_html_indented_configuration_as_amber():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_answer(
        console,
        "The configuration would be:\n\n&#x20;configure terminal\n&#x20;interface Ethernet0/1.15\n&#x20; shutdown\n&#x20;end\n\nNo change was made.",
    )
    rendered = output.getvalue()
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "&#x20;" not in rendered
    assert " shutdown" in rendered
    assert "No change was made." in rendered


def test_chat_fortios_configuration_uses_configuration_amber():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_answer(
        console,
        'FW01 configuration:\n\n```fortios\nconfig system interface\n    edit "port2"\n'
        '        set ip 10.0.12.3 255.255.255.0\n    next\nend\n```\n\nNo change was made.',
    )
    rendered = output.getvalue()
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "config system interface" in rendered and 'edit "port2"' in rendered
    assert "No change was made." in rendered


def test_chat_untagged_network_configuration_is_detected_as_amber():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_answer(
        console,
        'Configuration:\n\n```\nconfig firewall policy\nedit 1\nset action accept\nnext\nend\n```',
    )
    rendered = output.getvalue()
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "config firewall policy" in rendered


def test_chat_indented_fortios_configuration_is_recovered_as_amber():
    output = io.StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", no_color=False, width=120
    )
    render_answer(
        console,
        'FortiOS configuration:\n\n&#x20;config system interface\n&#x20; edit "port2"\n'
        '&#x20; set description "WAN"\n&#x20; next\n&#x20;end',
    )
    rendered = output.getvalue()
    assert "\x1b[38;2;255;209;102m" in rendered
    assert "config system interface" in rendered and "set description" in rendered


def test_devices_search_cli(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    metadata = tmp_path / "metadata.csv"
    metadata.write_text(
        "name,host,city,state,location,device_type\n"
        "fw1,192.0.2.2,Sample City,TX,Sample Data Center,firewall\n",
        encoding="utf-8",
    )
    Inventory(db_path).import_file(metadata)
    assert main([
        "--db", str(db_path), "devices", "search", "--location", "Sample City",
        "--device-type", "firewall",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert [device["name"] for device in result] == ["fw1"]


def test_devices_refresh_cli_mock(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--db", str(db_path), "devices", "refresh", "core", "--mock"
    ]) == 0
    result = json.loads(capsys.readouterr().out)[0]
    assert result["status"] == "success"
    assert result["record"]["device_hostname"] == "mock-device"
    assert result["record"]["model"] == "C9300-24T"
    assert result["record"]["serial_number"] == "FOC1234ABCD"


def test_health_cli_renders_mock_summary(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main(["--db", str(db_path), "health", "core", "--mock"]) == 0
    output = capsys.readouterr().out
    assert "Network Health" in output
    assert "core" in output
    assert "HEALTHY" in output
    assert "1/2 up" in output


def test_health_cli_json_and_unknown_device(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main(["--db", str(db_path), "health", "core", "--mock", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)[0]
    assert result["overall"] == "healthy"
    assert main(["--db", str(db_path), "health", "missing", "--mock"]) == 1
    assert "Unknown device" in capsys.readouterr().out


def test_route_trace_cli_returns_parsed_mock_evidence(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "route", "trace", "core", "2.2.2.2",
        "--workers", "1", "--mock", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["route_found"] is True
    assert result["next_hops"][0]["address"] == "192.0.2.2"
    assert result["commands"][0] == "show ip route 2.2.2.2"
    assert main([
        "--no-footer", "--db", str(db_path), "route", "trace", "core", "2.2.2.2",
        "--workers", "1", "--mock",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "OSPF route trace" in rendered and "Route evidence" in rendered


def test_topology_cli_discovers_and_reads_cached_mock_observations(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "topology", "discover", "core",
        "--workers", "1", "--mock", "--json",
    ]) == 1
    discovered = json.loads(capsys.readouterr().out)
    assert discovered["collection_counts"]["success"] == 1
    assert discovered["counts"]["unresolved"] == 1
    assert discovered["unresolved_neighbors"][0]["neighbor"] == "DIST-SW1"
    assert main([
        "--no-footer", "--db", str(db_path), "topology", "show", "core",
    ]) == 1
    rendered = capsys.readouterr().out
    assert "Network Topology: core" in rendered
    assert "Unresolved Neighbors" in rendered

    diagram_file = tmp_path / "topology.mmd"
    assert main([
        "--no-footer", "--db", str(db_path), "topology", "diagram", "core",
        "--format", "mermaid", "--output", str(diagram_file),
    ]) == 1
    assert diagram_file.read_text(encoding="utf-8").startswith("flowchart LR")
    assert "Saved mermaid topology diagram" in capsys.readouterr().out


def test_mac_path_cli_refreshes_and_renders_mock_observations(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "path", "mac", "0011.2233.4455",
        "--from", "core", "--refresh", "--workers", "1", "--mock", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["found"] is True and result["refreshed"] is True
    assert result["endpoint"]["interface"] == "Gi1/0/18"
    assert result["collection_counts"]["success"] == 1
    assert main([
        "--no-footer", "--db", str(db_path), "path", "mac", "0011.2233.4455",
        "--from", "core", "--mock",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "MAC Path: 00:11:22:33:44:55" in rendered
    assert "Endpoint: core Gi1/0/18" in rendered


def test_endpoint_cli_locates_ipv4_and_renders_attachment(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "endpoint", "locate", "10.20.0.45",
        "--refresh", "--workers", "1", "--mock", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["identifier_type"] == "ipv4"
    assert result["mac_addresses"] == ["00:11:22:33:44:55"]
    assert result["endpoints"][0]["endpoint"]["interface"] == "Gi1/0/18"

    assert main([
        "--no-footer", "--db", str(db_path), "endpoint", "locate", "10.20.0.45",
        "--mock",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "Endpoint: 10.20.0.45" in rendered
    assert "Gi1/0/18" in rendered


def test_mac_cli_scans_locates_and_troubleshoots_mock_endpoint(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "mac", "scan", "core", "--mock", "--json",
    ]) == 0
    captured = capsys.readouterr()
    scan = json.loads(captured.out)
    assert scan["counts"]["success"] == 1
    assert "Collecting current MAC observations from core..." in captured.err

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "locate", "00-11-22-33-44-55", "--json",
    ]) == 0
    location = json.loads(capsys.readouterr().out)
    assert location["likely_endpoint"]["interface"] == "Gi1/0/18"
    assert location["mock"] is True

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "troubleshoot", "0011.2233.4455", "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["healthy"] is True

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "locate", "0011.2233.4455",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "MAC 00:11:22:33:44:55" in rendered
    assert "Gi1/0/18" in rendered and "highest-ranked endpoint candidate" in rendered

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "port", "core",
        "GigabitEthernet1/0/18", "--json",
    ]) == 0
    port = json.loads(capsys.readouterr().out)
    assert port["count"] == 1 and port["observations"][0]["mac"] == "00:11:22:33:44:55"

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "table", "core", "--json",
    ]) == 0
    table = json.loads(capsys.readouterr().out)
    assert table["complete"] is True
    assert table["count"] >= 1
    assert table["observations"][0]["interface"]

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "table", "core",
    ]) == 0
    rendered = capsys.readouterr().out
    assert "MAC Address Table: core" in rendered
    assert "00:11:22:33:44:55" in rendered


def test_mac_cli_auto_collects_missing_observations_and_notifies(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "mac", "locate",
        "0011.2233.4455", "--workers", "1", "--mock", "--json",
    ]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["found"] is True
    assert result["refreshed"] is True
    assert result["refresh_reason"] == "missing_or_stale"
    assert result["collection_counts"]["success"] == 1
    assert (
        "MAC observations are missing or stale; collecting current data from "
        "all inventoried devices..."
    ) in captured.err

    assert main([
        "--no-footer", "--db", str(db_path), "mac", "locate",
        "0011.2233.4455", "--workers", "1", "--mock", "--json",
    ]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["refreshed"] is False
    assert "collecting current data" not in captured.err


def test_mac_table_cli_auto_collects_missing_observations_and_notifies(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "mac", "table", "core",
        "--workers", "1", "--mock", "--json",
    ]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["complete"] and result["refreshed"]
    assert result["refresh_reason"] == "missing_or_stale"
    assert result["collection_counts"]["success"] == 1
    assert "collecting current data from core" in captured.err


def test_arp_table_cli_auto_collects_and_returns_every_entry(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main([
        "--no-footer", "--db", str(db_path), "arp", "table", "core",
        "--workers", "1", "--mock", "--json",
    ]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["complete"] and result["refreshed"]
    assert result["refresh_reason"] == "missing_or_stale"
    assert result["observations"][0]["ip"] == "10.20.0.45"
    assert result["observations"][0]["mac"] == "00:11:22:33:44:55"
    assert "ARP observations are missing or stale; collecting current data from core" in captured.err

    assert main([
        "--no-footer", "--db", str(db_path), "arp", "table", "core", "--mock",
    ]) == 0
    captured = capsys.readouterr()
    assert "ARP Table: core" in captured.out
    assert "10.20.0.45" in captured.out and "00:11:22:33:44:55" in captured.out
    assert "collecting current data" not in captured.err


def test_execution_footer_shows_model_mcp_sources_and_counts():
    output = io.StringIO()
    trace = ExecutionTrace(
        started_at=10.0, finished_at=12.5, llm_used=True,
        llm_model="gpt-test-snapshot", llm_calls=2,
    )
    trace.record_tool("search_devices")
    trace.record_tool("get_device_facts")
    render_execution(Console(file=output, width=100, color_system=None), trace)
    rendered = output.getvalue()
    assert "Completed in 2.50s" in rendered
    assert "OpenAI: gpt-test-snapshot" in rendered
    assert "MCP: Local" in rendered
    assert "Local inventory + Live SSH" in rendered
    assert "LLM calls: 2" in rendered and "Tool calls: 2" in rendered
    assert "\\u2500" not in rendered


def test_direct_cli_footer_stays_out_of_json_and_can_be_disabled(tmp_path, capsys):
    db_path = inventory_path(tmp_path)
    assert main(["--db", str(db_path), "devices", "list"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)[0]["name"] == "core"
    assert "OpenAI: Not used" in captured.err
    assert "Data: Local inventory" in captured.err

    assert main(["--no-footer", "--db", str(db_path), "devices", "list"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)[0]["name"] == "core"
    assert "Completed in" not in captured.err
