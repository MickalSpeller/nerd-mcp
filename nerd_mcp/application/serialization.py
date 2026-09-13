"""Keep established terminal and MCP response shapes during migration."""
from dataclasses import asdict


def facts_legacy(result):
    facts = {key: value or "" for key, value in asdict(result.data).items()} if result.data is not None else {}
    successful = result.status in {"success", "partial"}
    return {
        "device": result.device, "commands": list(result.commands), "timestamp": result.timestamp,
        "status": "success" if successful else "error", "facts": facts,
        "warning": "Commands succeeded, but no supported device facts were parsed." if successful and not any(facts.values()) else None,
        "error": result.error, "mock": result.source == "mock",
    }


def interfaces_legacy(result):
    return {
        "device": result.device, "command": result.commands[0] if result.commands else None,
        "timestamp": result.timestamp,
        "status": "success" if result.status in {"success", "partial"} else "error",
        "output": result.raw_output, "error": result.error,
        "truncated": result.truncated, "mock": result.source == "mock",
    }


def health_legacy(assessment):
    metric_values = asdict(assessment.metrics)
    return {
        "overall": assessment.overall,
        "complete": assessment.complete,
        "counts": dict(assessment.counts),
        "metrics": {key: metric_values[key] for key in assessment.metric_fields},
        "checks": [
            {key: getattr(check, key) for key in ("id", "category", "severity", "summary")}
            for check in assessment.checks
        ],
    }


def ospf_status_legacy(result):
    status = result.data
    return {
        "device": result.device,
        "commands": list(result.commands),
        "timestamp": result.timestamp,
        "status": "success" if result.status in {"success", "partial"} else "error",
        "running": None if status is None else status.running,
        "process_count": 0 if status is None else len(status.processes),
        "processes": [] if status is None else [asdict(row) for row in status.processes],
        "neighbor_count": 0 if status is None else len(status.neighbors),
        "neighbors": [] if status is None else [asdict(row) for row in status.neighbors],
        "complete": False if status is None else status.complete,
        "warnings": list(result.warnings),
        "error": result.error,
        "mock": result.source == "mock",
    }


def bgp_status_legacy(result):
    status = result.data
    return {
        "device": result.device,
        "commands": list(result.commands),
        "timestamp": result.timestamp,
        "status": "success" if result.status in {"success", "partial"} else "error",
        "running": None if status is None else status.running,
        "router_id": None if status is None else status.router_id,
        "local_as": None if status is None else status.local_as,
        "neighbor_count": 0 if status is None else len(status.neighbors),
        "established_count": 0 if status is None else sum(
            row.established is True for row in status.neighbors
        ),
        "neighbors": [] if status is None else [asdict(row) for row in status.neighbors],
        "complete": False if status is None else status.complete,
        "warnings": list(result.warnings),
        "error": result.error,
        "mock": result.source == "mock",
    }


def vpn_status_legacy(result):
    status = result.data
    tunnels = () if status is None else status.ipsec_tunnels
    active_ipsec = sum(row.status == "up" for row in tunnels)
    return {
        "device": result.device,
        "commands": list(result.commands),
        "timestamp": result.timestamp,
        "status": (
            "success" if result.status == "success" else
            "partial" if result.status == "partial" else
            "unsupported" if result.status == "unsupported" else "error"
        ),
        "complete": False if status is None else status.complete,
        "has_active_vpn": None if status is None else status.has_active_vpn,
        "ipsec": {
            "complete": False if status is None else status.ipsec_complete,
            "tunnel_count": len(tunnels),
            "active_count": active_ipsec,
            "tunnels": [asdict(row) for row in tunnels],
        },
        "ssl_vpn": {
            "complete": False if status is None else status.ssl_vpn_complete,
            "active_session_count": (
                None if status is None else status.ssl_vpn_session_count
            ),
        },
        "warnings": list(result.warnings),
        "error": result.error,
        "mock": result.source == "mock",
    }


def configuration_legacy(result):
    snapshot = result.data
    return {
        "device": result.device,
        "command": result.commands[0] if result.commands else None,
        "source": "running" if snapshot is None else snapshot.source,
        "timestamp": result.timestamp,
        "status": "success" if result.status == "success" else "error",
        "output": "" if snapshot is None else snapshot.output,
        "error": result.error,
        "revision": None if snapshot is None else snapshot.revision,
        "total_chars": 0 if snapshot is None else snapshot.total_chars,
        "total_lines": 0 if snapshot is None else snapshot.total_lines,
        "redactions": 0 if snapshot is None else snapshot.redactions,
        "mock": result.source == "mock",
    }


def route_detail_legacy(route):
    return {
        "found": route.found,
        "prefix": route.prefix,
        "protocol": route.protocol,
        "distance": route.distance,
        "metric": route.metric,
        "route_type": route.route_type,
        "next_hops": [asdict(row) for row in route.next_hops],
        "route_source_router_ids": list(route.route_source_router_ids),
        "evidence": list(route.evidence),
    }


def ospf_neighbors_legacy(neighbors):
    return [asdict(row) for row in neighbors]


def ospf_database_legacy(database):
    return {
        "verified": database.verified,
        "advertising_router_ids": list(database.advertising_router_ids),
        "link_state_ids": list(database.link_state_ids),
    }
