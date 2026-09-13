"""Vendor-neutral health severity and assessment policy."""

from .models import (
    HealthAssessment,
    HealthFinding,
    HealthMetrics,
    HealthOverall,
    HealthSeverity,
)


CPU_WARNING_PERCENT = 75
CPU_CRITICAL_PERCENT = 90
MEMORY_WARNING_FREE_PERCENT = 20
MEMORY_CRITICAL_FREE_PERCENT = 10
SEVERITIES: tuple[HealthSeverity, ...] = ("critical", "warning", "ok", "info")


def finding(check_id: str, category: str, severity: HealthSeverity, summary: str) -> HealthFinding:
    complete = not check_id.endswith(("_unavailable", "_unparsed"))
    return HealthFinding(check_id, category, severity, summary, complete)


def cpu_severity(percent: int) -> HealthSeverity:
    if percent >= CPU_CRITICAL_PERCENT:
        return "critical"
    if percent >= CPU_WARNING_PERCENT:
        return "warning"
    return "ok"


def memory_severity(free_percent: float) -> HealthSeverity:
    if free_percent < MEMORY_CRITICAL_FREE_PERCENT:
        return "critical"
    if free_percent < MEMORY_WARNING_FREE_PERCENT:
        return "warning"
    return "ok"


def assess_health(
    metrics: HealthMetrics,
    checks: list[HealthFinding],
    metric_fields: tuple[str, ...],
) -> HealthAssessment:
    counts = {severity: sum(check.severity == severity for check in checks) for severity in SEVERITIES}
    overall: HealthOverall
    if counts["critical"]:
        overall = "critical"
    elif counts["warning"]:
        overall = "warning"
    elif counts["ok"]:
        overall = "healthy"
    else:
        overall = "unknown"
    return HealthAssessment(
        overall, all(check.complete for check in checks), counts, metrics, metric_fields, tuple(checks)
    )
