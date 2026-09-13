"""Dependency-free presentation of structured topology results."""

from collections.abc import Mapping

from .domain.errors import InventoryError


def escape_mermaid_text(value: str) -> str:
    """Escape untrusted inventory text for a quoted Mermaid label."""
    return (value or "").replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;"
    ).replace('"', "&quot;").replace("|", "&#124;")


def render_text_topology(topology: dict[str, object]) -> str:
    lines = []
    for link in topology["links"]:
        arrow = "<==>" if link["bidirectional"] else "--->"
        protocols = "/".join(link["protocols"]).upper()
        lines.append(
            f"[{link['a']['device']}] {link['a']['interface'] or '?'} {arrow} "
            f"{link['b']['interface'] or '?'} [{link['b']['device']}] "
            f"({protocols}, {link['confidence']})"
        )
    for row in topology["unresolved_neighbors"]:
        label = row["neighbor"] or row["neighbor_address"] or "unknown"
        lines.append(
            f"[{row['source']}] {row['interface'] or '?'} -?.. [{label}] "
            f"({row['protocol'].upper()}, unresolved)"
        )
    linked = {
        endpoint["device"] for link in topology["links"]
        for endpoint in (link["a"], link["b"])
    }
    unresolved_sources = {row["source"] for row in topology["unresolved_neighbors"]}
    for node in topology["nodes"]:
        if node["device"] not in linked | unresolved_sources:
            lines.append(f"[{node['device']}] (no correlated links)")
    return "\n".join(lines) or "No topology nodes or links matched."


def render_mermaid_topology(topology: dict[str, object]) -> str:
    nodes = {node["device"]: (f"n{index}", node)
             for index, node in enumerate(topology["nodes"])}
    lines = ["flowchart LR"]
    incomplete = {row["device"] for row in topology["incomplete_devices"]}
    for device, (node_id, node) in nodes.items():
        details = " · ".join(filter(None, (node["device_type"], node["vendor"], node["platform"])))
        place = node["location"] or ", ".join(filter(None, (node["city"], node["state"])))
        label = "<br/>".join(escape_mermaid_text(value) for value in (device, details, place) if value)
        lines.append(f'  {node_id}["{label}"]')
        classes = [
            node["device_type"].casefold()
            if node["device_type"].casefold() in {"router", "switch", "firewall"}
            else "device"
        ]
        if node.get("scope") == "boundary":
            classes.append("boundary")
        if device in incomplete:
            classes.append("incomplete")
        lines.append(f"  class {node_id} {','.join(classes)}")
    for link in topology["links"]:
        left, right = nodes[link["a"]["device"]][0], nodes[link["b"]["device"]][0]
        arrow = "<-->" if link["bidirectional"] else "-->"
        label = escape_mermaid_text(
            f"{link['a']['interface'] or '?'} / {link['b']['interface'] or '?'} · "
            f"{'/'.join(link['protocols']).upper()}"
        )
        lines.append(f'  {left} {arrow}|"{label}"| {right}')
    for index, row in enumerate(topology["unresolved_neighbors"]):
        unresolved_id = f"u{index}"
        label = escape_mermaid_text(row["neighbor"] or row["neighbor_address"] or "unknown")
        lines.append(f'  {unresolved_id}(["{label}<br/>unresolved"])')
        edge = escape_mermaid_text(f"{row['interface'] or '?'} · {row['protocol'].upper()}")
        lines.append(f'  {nodes[row["source"]][0]} -.->|"{edge}"| {unresolved_id}')
        lines.append(f"  class {unresolved_id} unresolved")
    lines.extend((
        "  classDef router fill:#102a43,stroke:#00d7ff,color:#ffffff",
        "  classDef switch fill:#123524,stroke:#4ade80,color:#ffffff",
        "  classDef firewall fill:#3b1d2a,stroke:#fb7185,color:#ffffff",
        "  classDef device fill:#26233a,stroke:#a78bfa,color:#ffffff",
        "  classDef boundary stroke-dasharray:5 5",
        "  classDef incomplete stroke:#f59e0b,stroke-width:3px",
        "  classDef unresolved fill:#3b2f12,stroke:#f59e0b,color:#ffffff,stroke-dasharray:5 5",
    ))
    return "\n".join(lines)


class TopologyDiagramPresenter:
    """Add a requested diagram representation to structured topology data."""

    def present(
        self, topology: Mapping[str, object], output_format: str
    ) -> dict[str, object]:
        if output_format not in {"text", "mermaid"}:
            raise InventoryError("format must be text or mermaid.")
        result = dict(topology)
        result["format"] = output_format
        result["diagram"] = (
            render_mermaid_topology(result)
            if output_format == "mermaid"
            else render_text_topology(result)
        )
        return result
