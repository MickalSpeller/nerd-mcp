import json
from unittest.mock import Mock

import pytest

from nerd_mcp.application.change_policy import ChangeAuthorizationError
from nerd_mcp.application.changes import parse_structured_request, translate_request
from nerd_mcp.bootstrap import build_application
from nerd_mcp.domain.errors import InventoryError
from nerd_mcp.inventory import Inventory
from nerd_mcp.vendors.change_adapters import ADAPTERS


def inventory_with(tmp_path, rows):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,vendor,platform\n" + "\n".join(
            f"{name},192.0.2.{number},{vendor},{platform}"
            for number, (name, vendor, platform) in enumerate(rows, 1)
        ) + "\n",
        encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return inventory


def request(devices=("R1",), operations=None):
    operations = operations or [{
        "kind": "interface_description",
        "values": {"interface": "Ethernet0/1", "description": "Branch uplink"},
    }]
    return parse_structured_request(json.dumps({"operations": operations}), devices)


def test_typed_request_rejects_raw_commands_and_injection():
    with pytest.raises(InventoryError, match="allowlisted"):
        request(operations=[{"kind": "raw_cli", "values": {"command": "reload"}}])
    with pytest.raises(InventoryError, match="only kind and values"):
        request(operations=[{
            "kind": "interface_admin", "values": {"interface": "e0/1", "enabled": False},
            "command": "reload",
        }])
    with pytest.raises(InventoryError, match="Management"):
        ADAPTERS["cisco_ios"].render(request(operations=[{
            "kind": "interface_admin", "values": {"interface": "management0", "enabled": False},
        }]).operations[0])


def test_ios_bgp_neighbor_supports_validated_update_source():
    operation = request(operations=[{
        "kind": "bgp_neighbor",
        "values": {
            "local_as": 65001, "neighbor": "2.2.2.2", "remote_as": 65001,
            "update_source": "Loopback0",
        },
    }]).operations[0]
    rendered = ADAPTERS["cisco_ios"].render(operation)
    assert rendered.commands == (
        "router bgp 65001",
        "neighbor 2.2.2.2 remote-as 65001",
        "neighbor 2.2.2.2 update-source Loopback0",
    )
    assert rendered.expected == rendered.commands[1:]


def test_bgp_update_source_rejects_unsafe_or_management_interface():
    for source in ("Loopback0; reload", "management0"):
        with pytest.raises(InventoryError):
            ADAPTERS["cisco_ios"].render(request(operations=[{
                "kind": "bgp_neighbor",
                "values": {
                    "local_as": 65001, "neighbor": "2.2.2.2", "remote_as": 65001,
                    "update_source": source,
                },
            }]).operations[0])


def test_multi_device_plan_binds_each_operation_to_its_named_target(tmp_path):
    app, _transport = build_live_app(tmp_path, ("R1", "R2"))
    change = request(("R1", "R2"), operations=[{
        "kind": "bgp_neighbor",
        "values": {
            "device": "R1", "local_as": 65001, "neighbor": "2.2.2.2",
            "remote_as": 65001, "update_source": "Loopback0",
        },
    }])
    plan = app.change_planning.plan(change)
    by_device = {row["device"]: row for row in plan["devices"]}
    assert by_device["R1"]["commands"] == (
        "router bgp 65001",
        "neighbor 2.2.2.2 remote-as 65001",
        "neighbor 2.2.2.2 update-source Loopback0",
    )
    assert by_device["R2"]["commands"] == ()
    assert by_device["R2"]["already_applied"] is True
    with pytest.raises(InventoryError, match="unsupported value"):
        ADAPTERS["cisco_ios"].render(request(operations=[{
            "kind": "interface_admin",
            "values": {"interface": "e0/1", "enabled": False, "command": "reload"},
        }]).operations[0])


def test_mock_plan_is_sanitized_durable_and_fortios_fails_closed(tmp_path):
    inventory = inventory_with(tmp_path, [("R1", "Cisco", "IOS/IOS-XE")])
    app = build_application(inventory, mock=True)
    plan = app.change_planning.plan(request())
    stored = app.changes.get(plan["change_id"])
    assert stored["state"] == "prepared"
    assert stored["devices"][0]["commands"] == [
        "interface Ethernet0/1", "description Branch uplink",
    ]
    assert "mock:R1" not in json.dumps(stored)
    assert app.changes.history()[0]["change_id"] == plan["change_id"]

    fortinet = inventory_with(tmp_path / "fortinet", [("FW1", "Fortinet", "FortiOS")])
    forti_app = build_application(fortinet, mock=True)
    with pytest.raises(InventoryError, match="remains read-only"):
        forti_app.change_planning.plan(request(("FW1",), [{
            "kind": "ntp_server", "values": {"address": "192.0.2.20"},
        }]))


@pytest.mark.parametrize("vendor,platform", [
    ("Cisco", "NX-OS"), ("Aruba", "AOS-CX"), ("Aruba", "AOS-Switch"),
])
def test_unvalidated_platform_write_adapters_fail_closed(tmp_path, vendor, platform):
    inventory = inventory_with(tmp_path, [("edge", vendor, platform)])
    app = build_application(inventory, mock=True)
    with pytest.raises(InventoryError, match="not supported on platform"):
        app.change_planning.plan(request(("edge",)))


def test_planner_normalizes_matching_repeated_device_from_any_caller(tmp_path):
    inventory = inventory_with(tmp_path, [("R1", "Cisco", "IOS/IOS-XE")])
    app = build_application(inventory, mock=True)
    duplicated = request(operations=[{
        "kind": "interface_description",
        "values": {
            "device": "r1", "interface": "Ethernet0/1",
            "description": "Branch uplink",
        },
    }])
    plan = app.change_planning.plan(duplicated)
    assert plan["request"]["operations"][0]["values"] == {
        "interface": "Ethernet0/1", "description": "Branch uplink",
    }


def test_authorization_is_exact_and_single_use(tmp_path):
    inventory = inventory_with(tmp_path, [("R1", "Cisco", "IOS/IOS-XE")])
    app = build_application(inventory, mock=True)
    plan = app.change_planning.plan(request())
    authorization = app.change_writes.authorize(plan["change_id"], "apply")
    loaded = app.change_writes.policy
    from nerd_mcp.application.changes import _plan_from_dict
    typed = _plan_from_dict(app.change_repository.get(plan["change_id"]))
    loaded.require(authorization, typed, "apply")
    with pytest.raises(ChangeAuthorizationError):
        loaded.require(authorization, typed, "apply")


class FakeTransport:
    def __init__(self, configs, fail_device=None):
        self.configs = dict(configs); self.checkpoints = {}; self.fail_device = fail_device
        self.calls = []

    def read_many(self, device, _driver, commands, _timeout, **_kwargs):
        config = self.configs[device.name]
        return ({key: config if "config" in command else "Version 1"
                 for key, command in commands.items()}, None)

    def execute_commands(self, device, _driver, commands, read_timeout=60):
        self.calls.append(("exec", device.name, tuple(commands)))
        if commands and (commands[0].startswith("copy running") or commands[0].startswith("checkpoint")):
            self.checkpoints[device.name] = self.configs[device.name]
        elif commands and ("configure replace" in commands[0] or "rollback" in commands[0]):
            self.configs[device.name] = self.checkpoints[device.name]
        return ("ok",)

    def send_config(self, device, _driver, commands, read_timeout=60):
        self.calls.append(("config", device.name, tuple(commands)))
        if device.name == self.fail_device:
            return "% Invalid input"
        self.configs[device.name] += "\n" + "\n".join(commands)
        return "ok"


def build_live_app(tmp_path, names=("R1",), fail=None):
    inventory = inventory_with(tmp_path, [(name, "Cisco", "IOS/IOS-XE") for name in names])
    transport = FakeTransport({name: f"hostname {name}" for name in names}, fail)
    app = build_application(inventory, mock=False)
    app.change_planning.transport = transport
    app.change_writes.transport = transport
    return app, transport


def test_apply_verify_and_separate_save(tmp_path):
    app, transport = build_live_app(tmp_path)
    plan = app.change_planning.plan(request())
    auth = app.change_writes.authorize(plan["change_id"], "apply")
    applied = app.change_writes.apply(plan["change_id"], authorization=auth)
    assert applied["state"] == "applied_pending_save"
    assert applied["devices"][0]["commands_completed"] == 2
    assert "interface Ethernet0/1" in applied["devices"][0]["live_configuration"]
    assert "description Branch uplink" in applied["devices"][0]["live_configuration"]
    assert not any("write memory" in commands for _, _, commands in transport.calls)
    save = app.change_writes.authorize(plan["change_id"], "save")
    assert app.change_writes.save(plan["change_id"], authorization=save)["state"] == "saved"
    assert any("write memory" in commands for _, _, commands in transport.calls)


def test_operator_can_roll_back_verified_unsaved_change(tmp_path):
    app, transport = build_live_app(tmp_path)
    plan = app.change_planning.plan(request())
    original = transport.configs["R1"]
    apply_auth = app.change_writes.authorize(plan["change_id"], "apply")
    assert app.change_writes.apply(
        plan["change_id"], authorization=apply_auth
    )["state"] == "applied_pending_save"
    rollback_auth = app.change_writes.authorize(plan["change_id"], "rollback")
    result = app.change_writes.rollback(plan["change_id"], authorization=rollback_auth)
    assert result["state"] == "rolled_back"
    assert result["devices"][0]["status"] == "rollback verified"
    assert transport.configs["R1"] == original


def test_batch_failure_rolls_back_every_touched_device_in_reverse(tmp_path):
    app, transport = build_live_app(tmp_path, ("R1", "R2", "R3"), fail="R3")
    plan = app.change_planning.plan(request(("R1", "R2", "R3")))
    auth = app.change_writes.authorize(plan["change_id"], "apply")
    result = app.change_writes.apply(plan["change_id"], authorization=auth)
    assert result["state"] == "rolled_back"
    failure = result["devices"][-1]
    assert failure["device"] == "R3"
    assert failure["stage"] == "configuration apply"
    assert failure["rollback"] == "verified"
    assert [name for action, name, commands in transport.calls
            if action == "exec" and commands and "configure replace" in commands[0]] == ["R3", "R2", "R1"]
    assert transport.configs == {"R1": "hostname R1", "R2": "hostname R2", "R3": "hostname R3"}


def test_stale_plan_never_creates_checkpoint(tmp_path):
    app, transport = build_live_app(tmp_path)
    plan = app.change_planning.plan(request())
    transport.configs["R1"] += "\nchanged elsewhere"
    auth = app.change_writes.authorize(plan["change_id"], "apply")
    result = app.change_writes.apply(plan["change_id"], authorization=auth)
    assert result["state"] == "failed"
    assert transport.calls == []


def test_live_preflight_shows_replaced_configuration(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Ethernet0/1\n description Old uplink\n!"
    )
    plan = app.change_planning.plan(request())
    preview = plan["devices"][0]
    assert preview["already_applied"] is False
    assert preview["configuration_diff"] == (
        "  interface Ethernet0/1",
        "- description Old uplink",
        "+ description Branch uplink",
    )


def test_live_preflight_resolves_loopback_abbreviation_by_previous_address(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255\n!"
    )
    change = request(operations=[{
        "kind": "interface_ipv4",
        "values": {
            "interface": "Loopback", "address": "10.10.10.10", "prefix_length": 24,
            "previous_address": "1.1.1.1",
        },
    }])
    plan = app.change_planning.plan(change)
    preview = plan["devices"][0]
    assert preview["commands"] == (
        "interface Loopback0", "ip address 10.10.10.10 255.255.255.0",
    )
    assert preview["configuration_diff"] == (
        "  interface Loopback0",
        "- ip address 1.1.1.1 255.255.255.255",
        "+ ip address 10.10.10.10 255.255.255.0",
    )


def test_loopback_delete_has_exact_diff_and_blocks_dependencies(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Loopback3\n ip address 33.33.33.33 255.255.255.0\n!"
    )
    change = request(operations=[{
        "kind": "interface_delete", "values": {"interface": "Loopback3"},
    }])
    plan = app.change_planning.plan(change)
    assert plan["devices"][0]["commands"] == ("no interface Loopback3",)
    assert plan["devices"][0]["configuration_diff"] == (
        "- interface Loopback3", "- ip address 33.33.33.33 255.255.255.0",
    )

    blocked, blocked_transport = build_live_app(tmp_path / "blocked")
    blocked_transport.configs["R1"] = (
        "hostname R1\nrouter bgp 65001\n neighbor 2.2.2.2 update-source Loopback3\n"
        "interface Loopback3\n ip address 33.33.33.33 255.255.255.0\n!"
    )
    with pytest.raises(InventoryError, match="other configuration references it"):
        blocked.change_planning.plan(change)


def test_physical_interface_deletion_is_blocked():
    with pytest.raises(InventoryError, match="Only numbered Loopback"):
        ADAPTERS["cisco_ios"].render(request(operations=[{
            "kind": "interface_delete", "values": {"interface": "Ethernet0/1"},
        }]).operations[0])


def test_bgp_interface_advertisement_derives_live_subnet_and_as(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Loopback3\n ip address 11.11.11.11 255.255.255.0\n!\n"
        "router bgp 65001\n bgp router-id 1.1.1.1\n!"
    )
    change = request(operations=[{
        "kind": "bgp_interface_network", "values": {"interface": "Loopback3"},
    }])
    plan = app.change_planning.plan(change)
    preview = plan["devices"][0]
    assert preview["commands"] == (
        "router bgp 65001", "network 11.11.11.0 mask 255.255.255.0",
    )
    assert preview["configuration_diff"] == (
        "  router bgp 65001", "+ network 11.11.11.0 mask 255.255.255.0",
    )


def test_bgp_interface_advertisement_rejects_missing_address_or_process(tmp_path):
    app, transport = build_live_app(tmp_path)
    change = request(operations=[{
        "kind": "bgp_interface_network", "values": {"interface": "Loopback3"},
    }])
    transport.configs["R1"] = "hostname R1\ninterface Loopback3\n!\nrouter bgp 65001\n!"
    with pytest.raises(InventoryError, match="exactly one supported live IPv4"):
        app.change_planning.plan(change)
    transport.configs["R1"] = (
        "hostname R1\ninterface Loopback3\n ip address 11.11.11.11 255.255.255.0\n!"
    )
    with pytest.raises(InventoryError, match="exactly one supported BGP process"):
        app.change_planning.plan(change)


def test_stale_check_ignores_volatile_show_version_output(tmp_path):
    app, transport = build_live_app(tmp_path)
    counter = {"value": 0}
    original = transport.read_many

    def changing_version(device, driver, commands, timeout, **kwargs):
        result, password = original(device, driver, commands, timeout, **kwargs)
        counter["value"] += 1
        for key, command in commands.items():
            if command == "show version":
                result[key] = f"uptime {counter['value']} seconds"
        return result, password

    transport.read_many = changing_version
    plan = app.change_planning.plan(request())
    authorization = app.change_writes.authorize(plan["change_id"], "apply")
    result = app.change_writes.apply(plan["change_id"], authorization=authorization)
    assert result["state"] == "applied_pending_save"


def test_live_preflight_detects_change_already_applied(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Ethernet0/1\n description Branch uplink\n!"
    )
    plan = app.change_planning.plan(request())
    assert plan["state"] == "already_applied"
    assert plan["devices"][0]["commands"] == ()
    with pytest.raises(ChangeAuthorizationError, match="prepared"):
        app.change_writes.authorize(plan["change_id"], "apply")


def test_parent_ip_change_rejects_existing_subinterface_dependency(tmp_path):
    app, transport = build_live_app(tmp_path)
    transport.configs["R1"] = (
        "hostname R1\ninterface Ethernet0/1.12\n encapsulation dot1Q 12\n"
        "interface Ethernet0/1.15\n encapsulation dot1Q 15\n!"
    )
    change = request(operations=[{
        "kind": "interface_ipv4",
        "values": {
            "interface": "Ethernet0/1", "address": "4.4.4.4",
            "prefix_length": 24,
        },
    }])
    with pytest.raises(InventoryError, match="while subinterfaces exist"):
        app.change_planning.plan(change)


def test_transport_write_redacts_password_and_uses_config_set(tmp_path, monkeypatch):
    inventory = inventory_with(tmp_path, [("R1", "Cisco", "IOS/IOS-XE")])
    known_hosts = tmp_path / "known_hosts"; known_hosts.write_text("host key")
    monkeypatch.setenv("NERD_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "operator")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "synthetic-secret")
    monkeypatch.setattr("nerd_mcp.credentials.read_saved", lambda _: None)
    session = Mock(); session.send_config_set.return_value = "ok synthetic-secret"
    from nerd_mcp.transport.netmiko import NetmikoTransport
    transport = NetmikoTransport(connector=Mock(return_value=session))
    assert transport.send_config(
        inventory.get("R1"), "cisco_ios", ("interface e0/1", "shutdown")
    ) == "ok [REDACTED]"
    session.send_config_set.assert_called_once_with(
        ["interface e0/1", "shutdown"], read_timeout=60, cmd_verify=True
    )
    session.disconnect.assert_called_once()


def test_change_operations_remain_terminal_only():
    from nerd_mcp.application.operations import OperationEffect, OPERATIONS
    write_effects = {OperationEffect.WRITE_DEVICE, OperationEffect.SAVE_DEVICE}
    writes = [row for row in OPERATIONS.values() if row.effects & write_effects]
    assert {row.name for row in writes} == {
        "apply_configuration_change", "save_configuration_change",
    }
    assert all(not row.mcp_exposed for row in writes)


def test_natural_language_translation_removes_matching_repeated_device(monkeypatch):
    response = Mock(output_text=json.dumps({
        "summary": "Describe the interface",
        "operations": [{
            "kind": "interface_description",
            "values_json": json.dumps({
                "device": "r1", "interface": "Ethernet0/1",
                "description": "Branch uplink",
            }),
        }],
    }))
    client = Mock(); client.responses.create.return_value = response
    context = Mock()
    context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("openai.OpenAI", Mock(return_value=context))

    translated = translate_request("Configure R1", ("R1",), "gpt-test")
    assert translated.operations[0].values == {
        "interface": "Ethernet0/1", "description": "Branch uplink",
    }


def test_natural_language_translation_rejects_different_device(monkeypatch):
    response = Mock(output_text=json.dumps({
        "summary": "Describe the interface",
        "operations": [{
            "kind": "interface_description",
            "values_json": json.dumps({
                "device": "R2", "interface": "Ethernet0/1",
                "description": "Branch uplink",
            }),
        }],
    }))
    client = Mock(); client.responses.create.return_value = response
    context = Mock(); context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("openai.OpenAI", Mock(return_value=context))
    with pytest.raises(InventoryError, match="outside the approved target scope"):
        translate_request("Configure R1", ("R1",), "gpt-test")


@pytest.mark.parametrize("values, expected", [
    ({"device": "R1", "interface": "Ethernet0/2", "address": "4.4.4.4/24"},
     {"interface": "Ethernet0/2", "address": "4.4.4.4", "prefix_length": 24}),
    ({"interface": "Ethernet0/2", "ip_address": "4.4.4.4", "prefix": 24},
     {"interface": "Ethernet0/2", "address": "4.4.4.4", "prefix_length": 24}),
    ({"interface": "Ethernet0/2", "address": "4.4.4.4", "subnet_mask": "255.255.255.0"},
     {"interface": "Ethernet0/2", "address": "4.4.4.4", "prefix_length": 24}),
    ({"interface": "Loopback0", "address": "10.10.10.10/24",
      "previous_address": "1.1.1.1"},
     {"interface": "Loopback0", "address": "10.10.10.10", "prefix_length": 24,
      "previous_address": "1.1.1.1"}),
    ({"interface": "Loopback0", "ipv4": "10.10.10.10/24"},
     {"interface": "Loopback0", "address": "10.10.10.10", "prefix_length": 24}),
    ({"interface": "Loopback0",
      "ipv4": {"address": "10.10.10.10", "prefix_length": 24}},
     {"interface": "Loopback0", "address": "10.10.10.10", "prefix_length": 24}),
])
def test_natural_language_translation_normalizes_ipv4_prefixes(monkeypatch, values, expected):
    response = Mock(output_text=json.dumps({
        "summary": "Change interface address",
        "operations": [{"kind": "interface_ipv4", "values_json": json.dumps(values)}],
    }))
    client = Mock(); client.responses.create.return_value = response
    context = Mock(); context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("openai.OpenAI", Mock(return_value=context))
    translated = translate_request("Change R1 Ethernet0/2 to 4.4.4.4/24", ("R1",), "gpt-test")
    assert translated.operations[0].values == expected


def test_natural_language_translation_rejects_invalid_previous_ipv4(monkeypatch):
    response = Mock(output_text=json.dumps({
        "summary": "Change interface address",
        "operations": [{"kind": "interface_ipv4", "values_json": json.dumps({
            "interface": "Loopback0", "address": "10.10.10.10/24",
            "previous_address": "1.1.1.1; reload",
        })}],
    }))
    client = Mock(); client.responses.create.return_value = response
    context = Mock(); context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("openai.OpenAI", Mock(return_value=context))
    with pytest.raises(InventoryError, match="invalid previous interface address"):
        translate_request("Change R1 Loopback0", ("R1",), "gpt-test")


def test_change_plan_has_natural_language_preview_and_exact_commands(tmp_path):
    from io import StringIO
    from rich.console import Console
    from nerd_mcp.presentation import render_change_plan

    inventory = inventory_with(tmp_path, [("R1", "Cisco", "IOS/IOS-XE")])
    plan = build_application(inventory, mock=True).change_planning.plan(request())
    output = StringIO()
    render_change_plan(Console(file=output, color_system=None, width=100), plan)
    rendered = output.getvalue()
    assert "Configuration Change CHG-" in rendered
    assert "Configuration change" in rendered
    assert "Targets: R1 | State: PREPARED" in rendered
    assert "Proposed configuration change:" in rendered
    assert "interface Ethernet0/1" in rendered
    assert "+ description Branch uplink" in rendered
    assert "Proposed configuration ─" not in rendered
    assert "No configuration has been changed" in rendered
