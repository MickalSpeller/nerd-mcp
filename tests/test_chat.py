import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from mcp.types import Tool, CallToolResult
from openai.types.responses import ResponseFunctionToolCall

from nerd_mcp.chat import (
    Chat, INSTRUCTIONS, MAX_CALLS, answer_with_status, requires_current_route_tool,
    requires_current_topology_tool, requires_current_mac_path_tool,
    requires_current_endpoint_tool, _baseline_update_intent, _change_followup_intent,
    _direct_change_intent, _is_yes_confirmation, _openai_failure_message,
    _proposal_requires_design_choice, _stored_change_command,
)
from nerd_mcp.chat_optimization import plan_question


def make_chat(responses):
    tool = Tool(name="get_interfaces", description="Read interfaces", inputSchema={
        "type": "object", "properties": {"device": {"type": "string"}}, "required": ["device"]})
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=responses)))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"status": "success", "output": "Gi1 up"})))
    return Chat(api, session, "configured-model", [tool])


def call(arguments='{"device":"core"}', name="get_interfaces"):
    return ResponseFunctionToolCall(type="function_call", name=name, arguments=arguments, call_id="call_1")


def test_configuration_change_intent_includes_explicit_followups():
    assert _direct_change_intent("Configure R1 Ethernet0/1")
    assert _direct_change_intent("on R1, change the Loopback0 description")
    assert _direct_change_intent("Please change R1 Loopback0")
    assert _direct_change_intent("Can you configure R1 Ethernet0/1?")
    assert _direct_change_intent("on R1 create a new Loopback3 interface")
    assert _direct_change_intent("Please delete VLAN 300 on SW1")
    assert _direct_change_intent("Rename VLAN 20 on SW1")
    assert _direct_change_intent("I want to delete Loopback3 from R1")
    assert _direct_change_intent("I'd like to remove Loopback3 from R1")
    assert _direct_change_intent("on R1, advertise Loopback3 into BGP")
    assert _direct_change_intent("Withdraw Loopback3 from BGP on R1")
    assert _change_followup_intent("lets make the change")
    assert _change_followup_intent("Apply that change.")
    assert _change_followup_intent("please proceed with this change")
    assert _change_followup_intent("make the proposed changes")
    assert _change_followup_intent("Apply the recommended change.")
    assert _change_followup_intent("add the suggested configuration to R1")
    assert _change_followup_intent("add the suggest configuration to R1")
    assert not _change_followup_intent("What change would you recommend?")


def test_baseline_update_intent_recognizes_explicit_device_requests():
    assert _baseline_update_intent("update R1 baseline")
    assert _baseline_update_intent("Refresh the configuration baseline for R1.")
    assert _baseline_update_intent("please update R1's baseline")
    assert not _baseline_update_intent("compare R1 to its baseline")
    assert not _baseline_update_intent("is R1's baseline current?")


def test_baseline_replacement_confirmation_ignores_case_and_whitespace():
    assert _is_yes_confirmation("yes")
    assert _is_yes_confirmation("YES")
    assert _is_yes_confirmation("  Yes  ")
    assert not _is_yes_confirmation("y")
    assert not _is_yes_confirmation("no")


def test_openai_quota_failure_has_safe_actionable_message():
    error = RuntimeError(
        "429 {'error': {'message': 'You have no credits remaining.', "
        "'code': 'credit_balance_exhausted'}}"
    )
    message = _openai_failure_message(error, "diagnosis")
    assert "no credits remaining" in message
    assert "OpenAI Platform billing" in message
    assert "No diagnosis or change plan was created" in message
    assert "429" not in message


def test_openai_transient_rate_limit_is_distinct_from_exhausted_credits():
    error = RuntimeError("Rate limit reached for requests per minute")
    message = _openai_failure_message(error, "diagnosis")
    assert "Wait briefly and retry" in message
    assert "credits remaining" not in message


def test_interactive_prompt_parses_exact_stored_change_commands():
    assert _stored_change_command("APPLY CHG-63E569BADF31") == (
        "apply", "CHG-63E569BADF31"
    )
    assert _stored_change_command("save chg-63e569badf31") == (
        "save", "CHG-63E569BADF31"
    )
    assert _stored_change_command("ROLLBACK CHG-63E569BADF31") == (
        "rollback", "CHG-63E569BADF31"
    )
    assert _stored_change_command("apply 63E569BADF31") is None
    assert _stored_change_command("apply CHG-63E569BADF31 now") is None


def test_mutually_exclusive_bgp_designs_require_operator_choice():
    assert _proposal_requires_design_choice(
        "The proposed fixes are alternatives: 1. eBGP using different ASNs. 2. iBGP using AS 65001."
    )
    assert not _proposal_requires_design_choice(
        "The proposed iBGP fix uses AS 65001 on both routers."
    )


async def test_round_trip():
    chat = make_chat([SimpleNamespace(output=[call()], output_text="", model="gpt-test-snapshot"),
                      SimpleNamespace(output=[], output_text="Gi1 is up on core.", model="gpt-test-snapshot")])
    assert await chat.ask("Inspect core") == "Gi1 is up on core."
    chat.session.call_tool.assert_awaited_once_with("get_interfaces", {"device": "core"})
    second = chat.api.responses.create.call_args.kwargs
    assert second["store"] is False
    assert any(item.get("type") == "function_call_output" for item in second["input"])
    assert chat.tools[0]["parameters"]["additionalProperties"] is False
    assert chat.last_execution.llm_model == "gpt-test-snapshot"
    assert chat.last_execution.llm_calls == 2
    assert chat.last_execution.mcp_tools == ["get_interfaces"]
    assert chat.last_execution.live_ssh_used is True
    assert chat.last_execution.finished_at is not None


async def test_current_route_question_requires_fresh_trace_tool():
    tool = Tool(name="trace_ospf_route", description="Trace OSPF route", inputSchema={
        "type": "object",
        "properties": {
            "device": {"type": "string"}, "destination": {"type": "string"},
            "workers": {"type": "integer"},
        },
        "required": ["device", "destination", "workers"],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[], output_text="R2 advertises the route.", model="gpt-test"),
    ])))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"status": "success", "advertising_device": "R2"},
    )))
    chat = Chat(api, session, "configured-model", [tool])
    answer = await chat.ask("What device is advertising the OSPF route 2.2.2.2 from R1?")
    assert answer == "R2 advertises the route."
    assert api.responses.create.await_count == 1
    request = api.responses.create.await_args.kwargs
    assert request["tool_choice"] == "none"
    assert any(item.get("type") == "function_call_output" for item in request["input"])
    session.call_tool.assert_awaited_once_with(
        "trace_ospf_route", {"device": "R1", "destination": "2.2.2.2", "workers": 4}
    )


def test_conceptual_route_questions_do_not_force_live_tools():
    assert requires_current_route_tool("What device advertises route 2.2.2.2?")
    assert requires_current_route_tool("How does R1 reach 2.2.2.2?")
    assert not requires_current_route_tool("What is an OSPF route?")
    assert not requires_current_route_tool("Is OSPF running on R1?")


async def test_empty_answer_after_tool_result_gets_one_answer_only_retry():
    chat = make_chat([
        SimpleNamespace(output=[call()], output_text="", model="gpt-test"),
        SimpleNamespace(output=[], output_text="", model="gpt-test"),
        SimpleNamespace(output=[], output_text="OSPF is running on R1.", model="gpt-test"),
    ])
    assert await chat.ask("Is OSPF running on R1?") == "OSPF is running on R1."
    assert chat.api.responses.create.await_count == 3
    retry = chat.api.responses.create.await_args_list[2].kwargs
    assert retry["tool_choice"] == "none"
    assert "Answer the user's original question now" in retry["instructions"]


async def test_initial_empty_answer_is_not_retried_without_tool_results():
    chat = make_chat([SimpleNamespace(output=[], output_text="", model="gpt-test")])
    assert await chat.ask("Hello") == "No answer returned. Try a more specific device question."
    assert chat.api.responses.create.await_count == 1


async def test_current_topology_question_requires_fresh_discovery_tool():
    tool = Tool(name="discover_topology", description="Discover topology", inputSchema={
        "type": "object",
        "properties": {
            "target": {"type": "string"}, "workers": {"type": "integer"},
            "max_age_minutes": {"type": "integer"},
        },
        "required": ["target", "workers", "max_age_minutes"],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[], output_text="R1 connects to SW1.", model="gpt-test"),
    ])))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"status": "success", "links": []},
    )))
    chat = Chat(api, session, "configured-model", [tool])
    assert await chat.ask("What is connected to R1?") == "R1 connects to SW1."
    assert api.responses.create.await_count == 1
    assert api.responses.create.await_args.kwargs["tool_choice"] == "none"
    session.call_tool.assert_awaited_once_with(
        "discover_topology", {"target": "R1", "workers": 4, "max_age_minutes": 60}
    )


def test_cached_and_conceptual_topology_questions_do_not_force_discovery():
    assert requires_current_topology_tool("What is connected to R1?")
    assert requires_current_topology_tool("Discover the current network topology")
    assert not requires_current_topology_tool("Show the cached topology for R1")
    assert not requires_current_topology_tool("What is network topology?")


async def test_current_mac_path_question_requires_refreshed_path_tool():
    tool = Tool(name="trace_mac_path", description="Trace MAC path", inputSchema={
        "type": "object",
        "properties": {
            "mac_address": {"type": "string"}, "source_device": {"type": "string"},
            "max_age_minutes": {"type": "integer"}, "refresh": {"type": "boolean"},
            "workers": {"type": "integer"},
        },
        "required": ["mac_address", "source_device", "max_age_minutes", "refresh", "workers"],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[], output_text="R1 reaches the endpoint through SW1.", model="gpt-test"),
    ])))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={
            "status": "success", "refreshed": True, "mock": False,
            "path_devices": ["R1", "SW1"],
        },
    )))
    chat = Chat(api, session, "configured-model", [tool])
    answer = await chat.ask("Trace the MAC path for 0011.2233.4455 from R1")
    assert answer == "R1 reaches the endpoint through SW1."
    assert api.responses.create.await_count == 1
    assert api.responses.create.await_args.kwargs["tool_choice"] == "none"
    assert chat.last_execution.live_ssh_used is True


def test_cached_mac_path_question_does_not_force_refresh():
    assert requires_current_mac_path_tool("Trace the MAC path for 0011.2233.4455")
    assert requires_current_mac_path_tool("Trace 00:11:22:33:44:55 from R1")
    assert requires_current_mac_path_tool("Show the path through the network for 001122-334455")
    assert not requires_current_mac_path_tool("Show the cached MAC path for 0011.2233.4455")


async def test_current_ip_endpoint_question_requires_refreshed_endpoint_tool():
    tool = Tool(name="locate_endpoint", description="Locate endpoint", inputSchema={
        "type": "object",
        "properties": {
            "identifier": {"type": "string"}, "source_device": {"type": "string"},
            "max_age_minutes": {"type": "integer"}, "refresh": {"type": "boolean"},
            "workers": {"type": "integer"},
        },
        "required": ["identifier", "source_device", "max_age_minutes", "refresh", "workers"],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[], output_text="It is connected to SW2 Et1/10.", model="gpt-test"),
    ])))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={
            "status": "success", "refreshed": True, "mock": False,
            "attachment_found": True,
        },
    )))
    chat = Chat(api, session, "configured-model", [tool])
    assert await chat.ask("Where is 10.20.0.45 connected?") == "It is connected to SW2 Et1/10."
    assert api.responses.create.await_count == 1
    assert api.responses.create.await_args.kwargs["tool_choice"] == "none"
    assert chat.last_execution.live_ssh_used is True


def test_cached_or_non_endpoint_ip_questions_do_not_force_endpoint_collection():
    assert requires_current_endpoint_tool("Where is 10.20.0.45 connected?")
    assert requires_current_endpoint_tool("Locate 00:11:22:33:44:55")
    assert not requires_current_endpoint_tool("Show cached location for 10.20.0.45")
    assert not requires_current_endpoint_tool("What device advertises route 2.2.2.2?")


async def test_question_html_entities_are_normalized():
    chat = make_chat([SimpleNamespace(output=[], output_text="Serial retrieved.")])
    assert await chat.ask("what is the serial number of R2&#x20;") == "Serial retrieved."
    first = chat.api.responses.create.call_args.kwargs["input"][0]
    assert first == {"role": "user", "content": "what is the serial number of R2"}


def test_identity_instructions_require_live_fallback():
    assert "call get_device_facts before concluding" in INSTRUCTIONS
    assert "does not save facts" in INSTRUCTIONS
    assert "call get_interface_macs" in INSTRUCTIONS
    assert "call\nget_device_macs" in INSTRUCTIONS
    assert "call get_device_arps" in INSTRUCTIONS
    assert "use trace_ospf_route" in INSTRUCTIONS
    assert "use get_ospf_status" in INSTRUCTIONS
    assert "use get_bgp_status in the current turn" in INSTRUCTIONS
    assert "call get_vpn_status" in INSTRUCTIONS
    assert "use get_configuration_baseline" in INSTRUCTIONS
    assert "use compare_configuration_baseline" in INSTRUCTIONS
    assert "terminal-only operations" in INSTRUCTIONS
    assert "approval-required snapshot proposal" in INSTRUCTIONS
    assert "no earlier changes occurred" in INSTRUCTIONS
    assert "use compare_all_configuration_baselines" in INSTRUCTIONS
    assert "use\nget_configuration_baseline_status" in INSTRUCTIONS
    assert "use discover_topology" in INSTRUCTIONS
    assert "Use get_topology only" in INSTRUCTIONS
    assert "call get_topology_diagram" in INSTRUCTIONS
    assert "call trace_mac_path with refresh true" in INSTRUCTIONS
    assert "call locate_endpoint with refresh true" in INSTRUCTIONS
    assert Chat._tool_succeeded({"status": "success", "result": {"status": "partial"}})


def test_bgp_status_questions_prefetch_current_summary_for_named_device():
    plan = plan_question(
        "How long has the BGP neighbor been established on R1?",
        {"get_bgp_status", "get_health", "get_routes"},
    )
    assert plan.mode == "prefetch"
    assert plan.tool == "get_bgp_status"


def test_bgp_route_questions_prefetch_current_bgp_table():
    plan = plan_question(
        "Show the BGP routes on R1",
        {"get_bgp_routes", "get_bgp_status", "get_routes"},
    )
    assert plan.mode == "prefetch"
    assert plan.tool == "get_bgp_routes"
    assert plan.arguments == {"device": "R1"}
    assert plan.arguments == {"device": "R1"}


def test_two_device_bgp_problem_prefetches_status_and_configuration_for_both():
    plan = plan_question(
        "There is a problem with BGP peering between R1 and R2; tell me what is wrong and suggest a fix.",
        {"get_bgp_status", "get_bgp_configuration", "get_health", "get_routes"},
    )
    assert plan.mode == "prefetch"
    assert plan.prefetch_steps == (
        ("get_bgp_status", {"device": "R1"}),
        ("get_bgp_configuration", {"device": "R1"}),
        ("get_bgp_status", {"device": "R2"}),
        ("get_bgp_configuration", {"device": "R2"}),
    )
    assert plan.max_calls == 1
    assert plan.verbosity == "high"


async def test_approved_snapshot_offer_continues_original_model_turn():
    tools = [
        Tool(name="compare_configuration_baseline", description="Compare", inputSchema={
            "type": "object",
            "properties": {
                "device": {"type": "string"}, "cursor": {"type": "integer"},
                "revision": {"type": "string"},
            },
            "required": ["device", "cursor", "revision"],
        }),
        Tool(name="get_configuration_baseline", description="Read baseline", inputSchema={
            "type": "object",
            "properties": {
                "device": {"type": "string"}, "cursor": {"type": "integer"},
                "revision": {"type": "string"},
            },
            "required": ["device", "cursor", "revision"],
        }),
    ]
    compare_call = ResponseFunctionToolCall(
        type="function_call", name="compare_configuration_baseline",
        arguments='{"device":"R1","cursor":0,"revision":""}', call_id="compare_1",
    )
    baseline_call = ResponseFunctionToolCall(
        type="function_call", name="get_configuration_baseline",
        arguments='{"device":"R1","cursor":0,"revision":""}', call_id="baseline_1",
    )
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[compare_call], output_text="", model="gpt-test"),
        SimpleNamespace(output=[baseline_call], output_text="", model="gpt-test"),
        SimpleNamespace(output=[], output_text="R1 currently has OSPF process 1.", model="gpt-test"),
    ])))
    missing = CallToolResult(content=[], structuredContent={
        "status": "error", "approval_required": True,
        "snapshot_proposal": {
            "action": "create", "device": "R1", "source": "running", "replace": False,
            "reason": "No baseline exists.",
        },
    })
    stored = CallToolResult(content=[], structuredContent={
        "status": "success", "device": "R1", "output": "router ospf 1", "complete": True,
    })
    session = SimpleNamespace(call_tool=AsyncMock(side_effect=[missing, stored]))
    approval = AsyncMock(return_value={
        "status": "success", "mock": False,
        "baseline": {"device": "R1", "source": "running"},
    })
    chat = Chat(api, session, "configured-model", tools)
    answer = await chat.ask("Review R1 against its baseline", snapshot_approval=approval)
    assert answer == "R1 currently has OSPF process 1."
    approval.assert_awaited_once()
    assert session.call_tool.await_count == 2
    first_output = next(
        item["output"] for item in api.responses.create.await_args_list[1].kwargs["input"]
        if item.get("type") == "function_call_output" and item.get("call_id") == "compare_1"
    )
    assert json.loads(first_output)["result"]["status"] == "snapshot_created"
    assert chat.last_execution.live_ssh_used is True


async def test_declined_snapshot_offer_is_asked_only_once_and_does_not_claim_live_ssh():
    tool = Tool(name="compare_configuration_baseline", description="Compare", inputSchema={
        "type": "object", "properties": {
            "device": {"type": "string"}, "cursor": {"type": "integer"},
            "revision": {"type": "string"},
        }, "required": ["device", "cursor", "revision"],
    })
    calls = [ResponseFunctionToolCall(
        type="function_call", name="compare_configuration_baseline",
        arguments='{"device":"R1","cursor":0,"revision":""}', call_id=f"compare_{index}",
    ) for index in (1, 2)]
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[calls[0]], output_text="", model="gpt-test"),
        SimpleNamespace(output=[calls[1]], output_text="", model="gpt-test"),
        SimpleNamespace(output=[], output_text="No baseline was created.", model="gpt-test"),
    ])))
    missing = CallToolResult(content=[], structuredContent={
        "status": "error", "approval_required": True,
        "snapshot_proposal": {
            "action": "create", "device": "R1", "source": "running", "replace": False,
        },
    })
    session = SimpleNamespace(call_tool=AsyncMock(return_value=missing))
    approval = AsyncMock(return_value={"status": "declined"})
    chat = Chat(api, session, "configured-model", [tool])
    assert await chat.ask("Compare R1", snapshot_approval=approval) == "No baseline was created."
    approval.assert_awaited_once()
    assert chat.last_execution.live_ssh_used is False


async def test_invalid_arguments_and_unknown_tool():
    chat = make_chat([])
    for item in [call('{"device":"core","command":"reload"}'), call('broken'), call(name="reload")]:
        assert (await chat.execute(item))["status"] == "error"
    chat.session.call_tool.assert_not_awaited()


async def test_bounded_loop():
    chat = make_chat([SimpleNamespace(output=[call()], output_text="")] * (MAX_CALLS + 1))
    assert "limit" in await chat.ask("Keep inspecting")
    assert chat.session.call_tool.await_count == 8
    assert chat.api.responses.create.call_args.kwargs["tool_choice"] == "none"
    assert chat.history == []


async def test_api_failure_keeps_history_clean():
    chat = make_chat([RuntimeError("API down")])
    try:
        await chat.ask("Inspect")
    except RuntimeError:
        pass
    assert chat.history == []


async def test_mcp_failure_is_returned_to_model():
    chat = make_chat([])
    chat.session.call_tool.side_effect = RuntimeError("sensitive")
    assert (await chat.execute(call())) == {"status": "error", "error": "MCP tool request failed."}


async def test_device_list_uses_zero_model_calls_and_local_rendering():
    tool = Tool(name="list_devices", description="List", inputSchema={
        "type": "object", "properties": {}, "required": [],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock()))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"devices": [{
            "name": "R1", "host": "192.0.2.1", "device_type": "router",
            "city": "Example City", "state": "NC", "model": "C8000V",
            "serial_number": "ABC123",
        }]},
    )))
    chat = Chat(api, session, "configured-model", [tool])
    answer = await chat.ask("list my devices")
    assert "Device Inventory" in answer and "R1" in answer and "C8000V" in answer
    api.responses.create.assert_not_awaited()
    assert chat.last_execution.llm_used is False
    assert chat.last_execution.path == "Local fast path"


async def test_location_inventory_search_is_local_and_filters_records():
    tool = Tool(name="list_devices", description="List", inputSchema={
        "type": "object", "properties": {}, "required": [],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock()))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"devices": [
            {"name": "FW1", "host": "192.0.2.1", "device_type": "firewall",
             "city": "Sample City", "state": "TX"},
            {"name": "R1", "host": "192.0.2.2", "device_type": "router",
             "city": "Example City", "state": "NC"},
        ]},
    )))
    chat = Chat(api, session, "configured-model", [tool])
    answer = await chat.ask("what firewall is located at Sample City")
    assert "FW1" in answer and "R1" not in answer
    api.responses.create.assert_not_awaited()


async def test_scoped_tools_can_expand_to_full_catalog():
    tools = [
        Tool(name="get_device_facts", description="Facts", inputSchema={
            "type": "object", "properties": {"device": {"type": "string"}},
            "required": ["device"],
        }),
        Tool(name="get_configuration", description="Config", inputSchema={
            "type": "object", "properties": {}, "required": [],
        }),
    ]
    expand = ResponseFunctionToolCall(
        type="function_call", name="request_full_tool_catalog", arguments="{}",
        call_id="expand_1",
    )
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=[
        SimpleNamespace(output=[expand], output_text="", model="gpt-test"),
        SimpleNamespace(output=[], output_text="Use the configuration tool.", model="gpt-test"),
    ])))
    session = SimpleNamespace(call_tool=AsyncMock())
    chat = Chat(api, session, "configured-model", tools)
    assert await chat.ask("Analyze inventory coverage for R2") == "Use the configuration tool."
    first_names = {tool["name"] for tool in api.responses.create.await_args_list[0].kwargs["tools"]}
    second_names = {tool["name"] for tool in api.responses.create.await_args_list[1].kwargs["tools"]}
    assert "request_full_tool_catalog" in first_names
    assert "get_configuration" not in first_names
    assert second_names == {"get_device_facts", "get_configuration"}
    session.call_tool.assert_not_awaited()


async def test_identity_question_prefetches_inventory_and_live_facts_before_one_model_call():
    tools = [
        Tool(name="get_inventory_device", description="Inventory", inputSchema={
            "type": "object", "properties": {"device": {"type": "string"}},
            "required": ["device"],
        }),
        Tool(name="get_device_facts", description="Facts", inputSchema={
            "type": "object", "properties": {"device": {"type": "string"}},
            "required": ["device"],
        }),
    ]
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
        output=[], output_text="R2's serial number is ABC123.", model="gpt-test",
    ))))
    session = SimpleNamespace(call_tool=AsyncMock(side_effect=[
        CallToolResult(content=[], structuredContent={"device": {"name": "R2", "serial_number": ""}}),
        CallToolResult(content=[], structuredContent={"status": "success", "facts": {
            "serial_number": "ABC123",
        }}),
    ]))
    chat = Chat(api, session, "configured-model", tools)
    assert await chat.ask("What is the serial number of R2?") == "R2's serial number is ABC123."
    assert [item.args[0] for item in session.call_tool.await_args_list] == [
        "get_inventory_device", "get_device_facts",
    ]
    assert api.responses.create.await_count == 1


async def test_mac_port_question_refreshes_then_reads_port_before_one_model_call():
    tools = [
        Tool(name="refresh_mac_observations", description="Refresh", inputSchema={
            "type": "object", "properties": {
                "target": {"type": "string"}, "workers": {"type": "integer"},
            }, "required": ["target", "workers"],
        }),
        Tool(name="get_interface_macs", description="Port MACs", inputSchema={
            "type": "object", "properties": {
                "device": {"type": "string"}, "interface": {"type": "string"},
                "max_age_minutes": {"type": "integer"},
            }, "required": ["device", "interface", "max_age_minutes"],
        }),
    ]
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
        output=[], output_text="SW2 Et1/1 has MAC 00:11:22:33:44:55.", model="gpt-test",
    ))))
    session = SimpleNamespace(call_tool=AsyncMock(side_effect=[
        CallToolResult(content=[], structuredContent={"status": "success", "mock": False}),
        CallToolResult(content=[], structuredContent={"status": "success", "observations": [{
            "mac": "00:11:22:33:44:55", "interface": "Et1/1",
        }]}),
    ]))
    chat = Chat(api, session, "configured-model", tools)
    answer = await chat.ask("What MAC address is showing on SW2 port e1/1?")
    assert "00:11:22:33:44:55" in answer
    assert [item.args[0] for item in session.call_tool.await_args_list] == [
        "refresh_mac_observations", "get_interface_macs",
    ]
    assert api.responses.create.await_count == 1


async def test_mac_table_question_refreshes_then_reads_device_table_before_one_model_call():
    tools = [
        Tool(name="refresh_mac_observations", description="Refresh", inputSchema={
            "type": "object", "properties": {
                "target": {"type": "string"}, "workers": {"type": "integer"},
            }, "required": ["target", "workers"],
        }),
        Tool(name="get_device_macs", description="Device MAC table", inputSchema={
            "type": "object", "properties": {
                "device": {"type": "string"}, "max_age_minutes": {"type": "integer"},
            }, "required": ["device", "max_age_minutes"],
        }),
    ]
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
        output=[], output_text="SW1 has MAC 00:11:22:33:44:55 on Gi1/0/18.", model="gpt-test",
    ))))
    session = SimpleNamespace(call_tool=AsyncMock(side_effect=[
        CallToolResult(content=[], structuredContent={"status": "success", "mock": False}),
        CallToolResult(content=[], structuredContent={
            "status": "success", "device": "SW1", "complete": True, "count": 1,
            "observations": [{
                "mac": "00:11:22:33:44:55", "interface": "Gi1/0/18", "vlan": "20",
            }],
        }),
    ]))
    chat = Chat(api, session, "configured-model", tools)
    answer = await chat.ask("show me the mac address table on SW1  &#x20;")
    assert "00:11:22:33:44:55" in answer
    assert [item.args[0] for item in session.call_tool.await_args_list] == [
        "refresh_mac_observations", "get_device_macs",
    ]
    assert session.call_tool.await_args_list[0].args[1] == {"target": "SW1", "workers": 4}
    assert api.responses.create.await_count == 1


async def test_arp_table_question_refreshes_then_reads_every_entry_before_one_model_call():
    tools = [
        Tool(name="refresh_mac_observations", description="Refresh", inputSchema={
            "type": "object", "properties": {
                "target": {"type": "string"}, "workers": {"type": "integer"},
            }, "required": ["target", "workers"],
        }),
        Tool(name="get_device_arps", description="Device ARP table", inputSchema={
            "type": "object", "properties": {
                "device": {"type": "string"}, "max_age_minutes": {"type": "integer"},
            }, "required": ["device", "max_age_minutes"],
        }),
    ]
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
        output=[], output_text="R1 has 10.20.0.45 at 00:11:22:33:44:55 on Vlan20.",
        model="gpt-test",
    ))))
    session = SimpleNamespace(call_tool=AsyncMock(side_effect=[
        CallToolResult(content=[], structuredContent={"status": "success", "mock": False}),
        CallToolResult(content=[], structuredContent={
            "status": "success", "device": "R1", "complete": True, "count": 1,
            "observations": [{
                "ip": "10.20.0.45", "mac": "00:11:22:33:44:55",
                "interface": "Vlan20", "vrf": "default",
            }],
        }),
    ]))
    chat = Chat(api, session, "configured-model", tools)

    answer = await chat.ask("show me the arp table on R1")

    assert "10.20.0.45" in answer and "00:11:22:33:44:55" in answer
    assert [item.args[0] for item in session.call_tool.await_args_list] == [
        "refresh_mac_observations", "get_device_arps",
    ]
    assert session.call_tool.await_args_list[0].args[1] == {"target": "R1", "workers": 4}
    assert api.responses.create.await_count == 1


async def test_vpn_question_reads_current_fortios_status_before_one_model_call():
    tool = Tool(name="get_vpn_status", description="VPN status", inputSchema={
        "type": "object", "properties": {"device": {"type": "string"}},
        "required": ["device"],
    })
    api = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=SimpleNamespace(
        output=[], output_text="Yes. FW01 has one active IPsec tunnel.", model="gpt-test",
    ))))
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={
            "status": "success", "complete": True, "has_active_vpn": True,
            "ipsec": {"active_count": 1},
            "ssl_vpn": {"active_session_count": 0}, "mock": False,
        },
    )))
    chat = Chat(api, session, "configured-model", [tool])

    answer = await chat.ask("does FW01 have any VPN tunnels?")

    assert answer == "Yes. FW01 has one active IPsec tunnel."
    session.call_tool.assert_awaited_once_with("get_vpn_status", {"device": "FW01"})
    assert api.responses.create.await_count == 1
    assert api.responses.create.await_args.kwargs["tool_choice"] == "none"
    assert chat.last_execution.live_ssh_used is True


async def test_history_is_bounded_and_old_turns_become_stale_summary():
    response = SimpleNamespace(output=[], output_text="Acknowledged.", model="gpt-test")
    chat = make_chat([])
    chat.api.responses.create = AsyncMock(return_value=response)
    for index in range(8):
        assert await chat.ask(f"General question {index}") == "Acknowledged."
    assert len(chat._turns) == 6
    latest_input = chat.api.responses.create.await_args.kwargs["input"]
    assert latest_input[0]["role"] == "developer"
    assert "operational facts as stale" in latest_input[0]["content"]


async def test_usage_and_stage_metrics_are_recorded():
    response = SimpleNamespace(
        output=[], output_text="Answer.", model="gpt-5.6-luna",
        usage={
            "input_tokens": 100, "output_tokens": 20,
            "input_tokens_details": {"cached_tokens": 64},
            "output_tokens_details": {"reasoning_tokens": 5},
        },
    )
    chat = make_chat([])
    chat.model = "gpt-5.6-luna"
    chat.api.responses.create = AsyncMock(return_value=response)
    assert await chat.ask("Explain spanning tree") == "Answer."
    trace = chat.last_execution
    assert (trace.input_tokens, trace.output_tokens, trace.cached_input_tokens,
            trace.reasoning_tokens) == (100, 20, 64, 5)
    request = chat.api.responses.create.await_args.kwargs
    assert request["reasoning"] == {"effort": "low"}
    assert request["text"] == {"verbosity": "medium"}
    assert request["prompt_cache_key"] == "nerd-mcp-chat-v1"


def test_model_facing_tool_result_is_valid_compact_json_and_preserves_status():
    chat = make_chat([])
    output = {"status": "success", "result": {
        "device": "R1", "command": "show test", "timestamp": "2026-01-01T00:00:00Z",
        "warnings": ["coverage incomplete"], "complete": False,
        "output": "x" * 50000,
    }}
    compact = chat._compact_output("get_interfaces", output)
    assert compact["chat_compacted"] is True
    assert compact["result"]["device"] == "R1"
    assert compact["result"]["complete"] is False
    assert "remaining text omitted" in compact["result"]["output"]
    json.loads(json.dumps(compact))


async def test_prefetched_answer_can_stream_without_a_second_model_call():
    tool = Tool(name="get_device_facts", description="Facts", inputSchema={
        "type": "object", "properties": {"device": {"type": "string"}},
        "required": ["device"],
    })
    final = SimpleNamespace(output=[], output_text="R1's serial is ABC123.", model="gpt-test")

    class Stream:
        def __init__(self):
            self.events = iter([
                SimpleNamespace(type="response.output_text.delta", delta="R1's serial "),
                SimpleNamespace(type="response.output_text.delta", delta="is ABC123."),
            ])

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self.events)
            except StopIteration:
                raise StopAsyncIteration

        async def get_final_response(self):
            return final

    responses = SimpleNamespace(create=AsyncMock(), stream=lambda **kwargs: Stream())
    api = SimpleNamespace(responses=responses)
    session = SimpleNamespace(call_tool=AsyncMock(return_value=CallToolResult(
        content=[], structuredContent={"status": "success", "facts": {"serial_number": "ABC123"}},
    )))
    chat = Chat(api, session, "configured-model", [tool])
    chunks = []
    answer = await chat.ask("What is the serial number of R1?", stream_callback=chunks.append)
    assert answer == "R1's serial is ABC123."
    assert "".join(chunks) == answer
    assert chat.last_answer_streamed is True
    responses.create.assert_not_awaited()


async def test_thinking_status_wraps_response_processing():
    events = []

    class Status:
        def __enter__(self):
            events.append("started")

        def __exit__(self, *args):
            events.append("stopped")

    class Console:
        def status(self, message, spinner):
            assert message == "[dim]Thinking…[/dim]"
            assert spinner == "dots"
            return Status()

    chat = SimpleNamespace(ask=AsyncMock(side_effect=lambda question: events.append(question) or "answer"))
    assert await answer_with_status(chat, "Inspect R1", Console()) == "answer"
    assert events == ["started", "Inspect R1", "stopped"]


async def test_thinking_status_pauses_for_snapshot_consent():
    events = []

    class Status:
        def __enter__(self):
            events.append("thinking-started")
            return self

        def __exit__(self, *args):
            events.append("thinking-stopped")

        def stop(self):
            events.append("status-paused")

        def start(self):
            events.append("status-resumed")

        def update(self, value):
            events.append(value)

    class Console:
        def status(self, message, spinner):
            return Status()

        def input(self, prompt):
            events.append(prompt)
            return "yes"

        def print(self, message, style):
            events.append(message)

    class SnapshotChat:
        async def capture_configuration_snapshot(self, proposal):
            events.append("captured")
            return {"status": "success"}

        async def ask(self, question, snapshot_approval):
            result = await snapshot_approval({
                "action": "create", "device": "R1", "source": "running", "replace": False,
            })
            assert result["status"] == "success"
            return "answer"

    assert await answer_with_status(SnapshotChat(), "Compare R1", Console()) == "answer"
    assert "captured" in events
    assert any("cannot recover earlier configuration state" in item for item in events)
