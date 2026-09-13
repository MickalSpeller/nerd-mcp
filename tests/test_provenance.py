"""Operational provenance remains independent from execution timing."""

from nerd_mcp.domain.provenance import OperationProvenance
from nerd_mcp.execution import ExecutionTrace


def test_provenance_classifies_local_live_and_mock_operations():
    provenance = OperationProvenance()
    provenance.record("search_devices", local_inventory=True)
    provenance.record("get_health", live_device=True)
    provenance.record("get_interfaces", live_device=True, mock=True)
    assert provenance.operations == ["search_devices", "get_health", "get_interfaces"]
    assert provenance.data_sources() == ["Local inventory", "Mock device", "Live SSH"]


def test_failed_live_operation_does_not_claim_device_access():
    provenance = OperationProvenance()
    provenance.record("get_health", live_device=True, successful=False)
    assert provenance.data_sources(model_used=True) == ["Conversation context"]


def test_execution_trace_compatibility_properties_forward_to_provenance():
    trace = ExecutionTrace()
    trace.local_system_used = True
    trace.record_tool("get_health", mock=True, elapsed_seconds=0.25)
    assert trace.mcp_tools == ["get_health"]
    assert trace.mock_used is True and trace.live_ssh_used is False
    assert trace.local_system_used is True
    assert trace.mcp_seconds == 0.25
    assert trace.data_sources() == ["Mock device", "Local system"]
