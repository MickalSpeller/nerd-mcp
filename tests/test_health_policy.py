"""Typed health parsing and vendor-neutral policy coverage."""

from nerd_mcp.application.serialization import health_legacy
from nerd_mcp.domain.health import (
    assess_health,
    cpu_severity,
    finding,
    memory_severity,
)
from nerd_mcp.domain.models import HealthAssessment, HealthFinding, HealthMetrics
from nerd_mcp.vendors.cisco.ios import health as ios_health
from nerd_mcp.vendors.fortinet.fortios import health as fortios_health


def test_resource_thresholds_live_in_domain_policy():
    assert [cpu_severity(value) for value in (74, 75, 89, 90)] == [
        "ok", "warning", "warning", "critical"
    ]
    assert [memory_severity(value) for value in (20, 19.9, 10, 9.9)] == [
        "ok", "warning", "warning", "critical"
    ]


def test_policy_aggregates_typed_findings_with_severity_precedence():
    checks = [
        finding("available", "system", "ok", "Available."),
        finding("degraded", "resources", "warning", "Degraded."),
        finding("failed", "routing", "critical", "Failed."),
        finding("unknown", "interfaces", "info", "Unknown."),
    ]
    assessment = assess_health(
        HealthMetrics(cpu_five_minute_percent=95),
        checks,
        ("cpu_five_minute_percent",),
    )
    assert isinstance(assessment, HealthAssessment)
    assert all(isinstance(check, HealthFinding) for check in assessment.checks)
    assert assessment.overall == "critical"
    assert assessment.counts == {"critical": 1, "warning": 1, "ok": 1, "info": 1}
    assert health_legacy(assessment)["metrics"] == {"cpu_five_minute_percent": 95}


def test_ios_parser_returns_typed_health_and_preserves_legacy_shape():
    assessment = ios_health.parse_health(dict(ios_health.MOCK_OUTPUTS), "switch")
    result = health_legacy(assessment)
    assert isinstance(assessment.metrics, HealthMetrics)
    assert assessment.overall == "healthy" and assessment.complete is True
    assert result["metrics"]["interfaces_admin_down"] == 1
    assert result["metrics"]["cpu_five_minute_percent"] == 3
    assert all(set(check) == {"id", "category", "severity", "summary"} for check in result["checks"])


def test_ios_parser_keeps_unsupported_commands_unknown_and_incomplete():
    rejected = "% Invalid input detected at '^' marker."
    assessment = ios_health.parse_health({key: rejected for key in ios_health.COMMANDS})
    result = health_legacy(assessment)
    assert result["overall"] == "unknown" and result["complete"] is False
    assert result["counts"] == {"critical": 0, "warning": 0, "ok": 0, "info": 8}
    assert all(value is None for value in result["metrics"].values())


def test_fortios_parser_retains_vendor_metric_fields_and_malformed_state():
    healthy = health_legacy(fortios_health.parse_health(dict(fortios_health.MOCK_OUTPUTS)))
    malformed = health_legacy(fortios_health.parse_health({key: "garbled" for key in fortios_health.COMMANDS}))
    assert healthy["overall"] == "healthy" and healthy["complete"] is True
    assert "interfaces_admin_down" not in healthy["metrics"]
    assert malformed["complete"] is False
    assert malformed["counts"]["info"] >= 1
