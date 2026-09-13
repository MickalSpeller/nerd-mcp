"""NERD terminal banner, prompt, and color palette for interactive chat."""

import re

from rich.console import Console
from rich import box
from rich.markdown import Markdown
from rich.table import Table
from rich.text import Text

PRIMARY_COLOR = "#00D7FF"
BANNER_COLOR = "#00D9FF"
PROMPT_COLOR = "green"
CONFIG_COLOR = "#FFD166"
CONFIG_ADDED_COLOR = "#7EE787"
CONFIG_REMOVED_COLOR = "#FF7B72"
CONFIG_LANGUAGES = {
    "ios", "iosxe", "nxos", "cisco", "fortios", "fortigate", "aruba", "aoscx",
    "junos", "eos", "routeros", "network", "network-config", "config", "configuration", "cli",
}
NERD_BANNER = r"""
███╗   ██╗     ███████╗     ██████╗      ██████╗
████╗  ██║     ██╔════╝     ██╔══██╗     ██╔══██╗
██╔██╗ ██║     █████╗       ██████╔╝     ██║  ██║
██║╚██╗██║     ██╔══╝       ██╔══██╗     ██║  ██║
██║ ╚████║ ██╗ ███████╗ ██╗ ██║  ██║ ██╗ ██████╔╝ ██╗
╚═╝  ╚═══╝ ╚═╝ ╚══════╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝ ╚═════╝  ╚═╝
"""


def header(console: Console, mock: bool = False) -> None:
    """Render NERD v2 branding for an interactive chat session."""
    console.print()
    console.print(NERD_BANNER, style=f"bold {BANNER_COLOR}")
    console.print("[bold white]Network Engineering Reconnaissance & Discovery[/bold white]")
    console.print()
    if mock:
        console.print("[yellow]MOCK MODE · simulated device data · OpenAI API remains live[/yellow]")
        console.print()
    console.print("[dim]Ask about your network or type /reset, /footer on|off, or /exit.[/dim]")
    console.print()


def read_prompt(console: Console) -> str:
    """Read one question using the exact NERD v2 prompt."""
    return console.input(f"[bold {PROMPT_COLOR}]Ask N.E.R.D. › [/bold {PROMPT_COLOR}]")


def render_answer(console: Console, value: str) -> None:
    """Render model Markdown and highlight network configuration blocks in amber."""
    normalized = value.replace("&#x20;", " ").replace("&nbsp;", " ").replace("\u00a0", " ")
    normalized = "\n".join(line.rstrip() for line in normalized.splitlines()).strip()
    normalized = _fence_indented_configuration(normalized)
    lines = normalized.splitlines()
    prose: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("```"):
            prose.append(line)
            index += 1
            continue
        _render_markdown(console, "\n".join(prose))
        prose = []
        language = line[3:].strip().casefold()
        block: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != "```":
            block.append(lines[index])
            index += 1
        index += int(index < len(lines))
        if language in CONFIG_LANGUAGES or _looks_like_configuration(block):
            console.print()
            render_configuration(console, "\n".join(block))
            console.print()
        else:
            fence = f"```{language}\n" + "\n".join(block) + "\n```"
            _render_markdown(console, fence)
    _render_markdown(console, "\n".join(prose))


def _render_markdown(console: Console, value: str) -> None:
    if not value.strip():
        return
    markdown = Markdown(value.strip())
    for segments in console.render_lines(markdown, console.options, pad=False):
        line = Text.assemble(*(
            (segment.text.rstrip("\r\n"), segment.style) for segment in segments
        ))
        line.rstrip()
        console.print(line)


def _fence_indented_configuration(value: str) -> str:
    """Recover configuration blocks whose leading spaces arrived as HTML entities."""
    command_start = re.compile(
        r"^(?:configure\s+terminal|interface\b|router\b|line\b|vlan\b|hostname\b|"
        r"ip\b|ipv6\b|encapsulation\b|description\b|shutdown\b|no\b|end\b|exit\b|"
        r"switchport\b|spanning-tree\b|snmp-server\b|access-list\b|route-map\b|"
        r"config\b|edit\b|set\b|unset\b|next\b|delete\b|policy-map\b|class-map\b)",
        re.IGNORECASE,
    )
    lines = value.splitlines()
    output: list[str] = []
    index = 0
    in_fence = False
    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            in_fence = not in_fence
            output.append(line)
            index += 1
            continue
        if not in_fence and line[:1].isspace() and command_start.match(line.strip()):
            block = []
            while index < len(lines) and lines[index][:1].isspace() and lines[index].strip():
                block.append(lines[index][1:])
                index += 1
            output.extend(("```config", *block, "```"))
            continue
        output.append(line)
        index += 1
    return "\n".join(output)


def _looks_like_configuration(block: list[str]) -> bool:
    """Recognize untagged vendor configuration while leaving ordinary code alone."""
    meaningful = [line.strip() for line in block if line.strip() and not line.lstrip().startswith(("#", "//"))]
    if not meaningful:
        return False
    markers = re.compile(
        r"^(?:config(?:ure\s+terminal|\s+system|\s+router|\s+firewall)?\b|edit\b|set\b|"
        r"unset\b|next$|end$|interface\b|router\b|hostname\b|vlan\b|line\b|"
        r"switchport\b|ip\s+(?:address|route|access-list|ospf)\b|ipv6\b|snmp-server\b|"
        r"access-list\b|route-map\b|policy-map\b|class-map\b|no\s+shutdown\b|shutdown$)",
        re.IGNORECASE,
    )
    matches = sum(bool(markers.match(line)) for line in meaningful)
    structured = any(line.casefold().startswith(("config ", "interface ", "router ")) for line in meaningful)
    return matches >= 2 and structured


def render_configuration(console: Console, value: str) -> None:
    """Render configuration, distinguishing additions and removals in diff blocks."""
    for line in value.splitlines() or [""]:
        if line.startswith("+++") or line.startswith("---"):
            style = f"bold {PRIMARY_COLOR}"
        elif line.startswith("+"):
            style = CONFIG_ADDED_COLOR
        elif line.startswith("-"):
            style = CONFIG_REMOVED_COLOR
        elif line.startswith("@@"):
            style = "yellow"
        else:
            style = CONFIG_COLOR
        console.print(line, style=style, markup=False, highlight=False, soft_wrap=True)


def render_change_plan(console: Console, plan: dict) -> None:
    """Render a stored change plan as an operator-readable approval preview."""
    state = plan.get("state", "prepared").replace("_", " ").upper()
    devices = plan.get("devices", [])
    names = ", ".join(row["device"] for row in devices)
    summary = plan.get("request", {}).get("summary") or "Configuration change"
    console.print(Text(f"Configuration Change {plan['change_id']}", style=f"bold {PRIMARY_COLOR}"))
    console.print(summary, markup=False)
    console.print(
        f"Targets: {names} | State: {state} | Plan revision: {plan['revision'][:12]}",
        style="dim", markup=False,
    )
    for row in devices:
        console.print()
        console.print(Text(
            f"Changes for {row['device']} ({row['platform']})",
            style=f"bold {PRIMARY_COLOR}",
        ))
        impacts = ", ".join(dict.fromkeys(row.get("impact", [])))
        if impacts:
            console.print("This plan changes: " + impacts + ".", markup=False)
        if row.get("already_applied"):
            console.print(
                "Live configuration already satisfies this request:", style="bold green"
            )
        else:
            console.print("Proposed configuration change:", style="bold white")
        diff = row.get("configuration_diff") or [
            "+ " + command for command in row.get("commands", [])
        ]
        for line in diff or ["  (no commands)"]:
            if line.startswith("+"):
                style = f"bold {CONFIG_ADDED_COLOR}"
            elif line.startswith("-"):
                style = f"bold {CONFIG_REMOVED_COLOR}"
            else:
                style = CONFIG_COLOR
            console.print(line, style=style, markup=False, highlight=False, soft_wrap=True)
        checks = row.get("verification", [])
        if checks:
            expected = [item for check in checks for item in check.get("contains", [])]
            absent = [item for check in checks for item in check.get("excludes", [])]
            detail = []
            if expected:
                detail.append("confirm: " + "; ".join(expected))
            if absent:
                detail.append("confirm absent: " + "; ".join(absent))
            console.print(
                "Verification: " + (" | ".join(detail) or "validate the resulting configuration"),
                style="dim", markup=False,
            )
        console.print(
            "Recovery: create a pre-change checkpoint and restore it if apply or verification fails.",
            style="dim", markup=False,
        )
        save = ", ".join(row.get("save_commands", [])) or "platform transaction commit"
        console.print(
            f"Persistence after separate SAVE approval: {save}", style="dim", markup=False
        )
    if plan.get("state") == "prepared":
        console.print()
        console.print(
            "No configuration has been changed. Review the commands above before approving.",
            style="bold yellow", markup=False,
        )
    elif plan.get("state") == "already_applied":
        console.print()
        console.print(
            "No change is required, so NERD will not offer an APPLY action.",
            style="bold green", markup=False,
        )


def render_change_result(console: Console, result: dict) -> None:
    """Render apply/save/rollback results without exposing internal JSON."""
    state = result.get("state", "unknown").replace("_", " ").upper()
    style = "green" if state in {"SAVED", "APPLIED PENDING SAVE"} else "yellow"
    if state == "FAILED":
        style = "red"
    console.print(Text(f"Change {result.get('change_id', '')}: {state}", style=f"bold {style}"))
    for row in result.get("devices", []):
        console.print(f"• {row['device']}: {row['status']}", markup=False)
        if row.get("stage"):
            console.print(f"  Stage: {row['stage']}", style="yellow", markup=False)
        if row.get("reason"):
            console.print(f"  Reason: {row['reason']}", style="red", markup=False)
        if row.get("rollback"):
            console.print(f"  Rollback: {row['rollback']}", style="dim", markup=False)
        if row.get("live_configuration"):
            console.print("  Live affected configuration:", style="bold white")
            render_configuration(console, row["live_configuration"])
    if result.get("error"):
        console.print(result["error"], style="red", markup=False)


def render_diagnosis(console: Console, report: dict) -> None:
    """Render evidence-grounded root cause and any controlled recommendation."""
    root = report["root_cause"]
    console.print(Text(
        f"Diagnosis {report['diagnosis_id']}", style=f"bold {PRIMARY_COLOR}"
    ))
    console.print()
    console.print(f"ROOT CAUSE — {root['confidence'].upper()} CONFIDENCE", style="bold white")
    console.print(root["summary"], markup=False)
    if root.get("evidence"):
        console.print()
        console.print("SUPPORTING EVIDENCE", style="bold white")
        for item in root["evidence"]:
            console.print("• " + item, markup=False)
    findings = root.get("incorrect_configuration") or []
    if not findings and report.get("plan"):
        findings = [
            {
                "device": row["device"],
                "lines": [line[2:] for line in row.get("configuration_diff", ())
                          if line.startswith("- ")],
            }
            for row in report["plan"].get("devices", ())
            if any(line.startswith("- ") for line in row.get("configuration_diff", ()))
        ]
    if findings:
        console.print()
        console.print("INCORRECT LIVE CONFIGURATION", style="bold white")
        for finding in findings:
            console.print(f"{finding['device']}:", style=f"bold {CONFIG_COLOR}", markup=False)
            for line in finding.get("lines", ()):
                console.print("  - " + line, style=f"bold {CONFIG_REMOVED_COLOR}",
                              markup=False, highlight=False, soft_wrap=True)
    recommendation = report.get("recommendation") or {}
    if recommendation.get("summary"):
        console.print()
        console.print("RECOMMENDED CORRECTION", style="bold white")
        console.print(recommendation["summary"], markup=False)
    if report.get("plan"):
        plan = report["plan"]
        changed = [row for row in plan.get("devices", ()) if not row.get("already_applied")]
        console.print()
        console.print("PROPOSED CONFIGURATION DIFF", style="bold white")
        console.print(
            f"Change {plan['change_id']} | Affected devices: "
            + (", ".join(row["device"] for row in changed) or "none"),
            style="dim", markup=False,
        )
        for row in changed:
            console.print()
            console.print(f"{row['device']} ({row['platform']}):",
                          style=f"bold {PRIMARY_COLOR}", markup=False)
            for raw_line in row.get("configuration_diff", ()):
                line = "+ " + raw_line[2:] if raw_line.startswith("* ") else raw_line
                if line.startswith("+"):
                    style = f"bold {CONFIG_ADDED_COLOR}"
                elif line.startswith("-"):
                    style = f"bold {CONFIG_REMOVED_COLOR}"
                else:
                    style = CONFIG_COLOR
                console.print("  " + line, style=style, markup=False,
                              highlight=False, soft_wrap=True)
        unchanged = [row["device"] for row in plan.get("devices", ())
                     if row.get("already_applied")]
        if unchanged:
            console.print()
            console.print(
                "Already correct: " + ", ".join(unchanged), style="dim green", markup=False
            )
        console.print()
        console.print(
            "No configuration has been changed. Choose Apply to continue, Details for "
            "verification and recovery information, or Ignore.",
            style="bold yellow", markup=False,
        )
    elif report.get("planning_error"):
        console.print(
            "No applicable plan was created: " + report["planning_error"],
            style="yellow", markup=False,
        )
    if report["state"] == "inconclusive":
        console.print("NERD will not offer Apply because the diagnosis is inconclusive.",
                      style="bold yellow")
        for step in recommendation.get("next_steps", []):
            console.print("• " + step, style="yellow", markup=False)


def render_baselines(console: Console, result: dict) -> None:
    """Render metadata for every retained configuration baseline."""
    table = Table(title="Configuration Baselines", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Source", width=8, no_wrap=True)
    table.add_column("Captured (UTC)", no_wrap=True)
    table.add_column("Revision", width=12, no_wrap=True)
    table.add_column("Lines", justify="right")
    table.add_column("Redacted", justify="right")
    table.add_column("Mode", width=6, no_wrap=True)
    for baseline in result["baselines"]:
        table.add_row(
            baseline["device"], baseline["source"],
            baseline["captured_at"].replace("+00:00", "Z")[:20],
            baseline["revision"][:12], str(baseline["total_lines"]),
            str(baseline["redactions"]), "mock" if baseline["mock"] else "live",
        )
    console.print(table)


def render_baseline_metadata(console: Console, baseline: dict) -> None:
    """Render the provenance of one stored baseline."""
    console.print(Text(
        f"Configuration baseline: {baseline['device']}", style=f"bold {PRIMARY_COLOR}"
    ))
    console.print(
        f"Source: {baseline['source']} | Captured: {baseline['captured_at']} | "
        f"Revision: {baseline['revision'][:12]} | Lines: {baseline['total_lines']} | "
        f"Redacted: {baseline['redactions']} | "
        f"Mode: {'mock' if baseline['mock'] else 'live'}",
        markup=False,
    )


def render_baseline_comparison(console: Console, result: dict) -> None:
    """Render comparison status and a readable unified configuration diff."""
    if result["status"] != "success":
        console.print(result.get("error") or "Configuration comparison failed.", style="red", markup=False)
        return
    state = "CHANGED" if result["changed"] else "UNCHANGED"
    state_style = "yellow" if result["changed"] else "green"
    console.print(Text(f"Configuration baseline comparison: {result['device']}", style=f"bold {PRIMARY_COLOR}"))
    console.print(
        f"{state} | Source: {result['source']} | Baseline: {result['baseline_captured_at']} | "
        f"Compared: {result['compared_at']} | +{result['added_lines']} / -{result['removed_lines']}",
        style=state_style,
        markup=False,
    )
    if not result["diff"]:
        console.print("No configuration differences after volatile display metadata was ignored.", style="dim")
        return
    console.print()
    for line in result["diff"].splitlines():
        if line.startswith(("+++", "---")):
            style = f"bold {PRIMARY_COLOR}"
        elif line.startswith("+"):
            style = CONFIG_ADDED_COLOR
        elif line.startswith("-"):
            style = CONFIG_REMOVED_COLOR
        elif line.startswith("@@"):
            style = "yellow"
        else:
            style = CONFIG_COLOR
        console.print(line, style=style, markup=False, highlight=False, soft_wrap=True)


def render_fleet_baseline_comparison(console: Console, result: dict) -> None:
    """Render a compact fleet configuration-drift report without full diffs."""
    styles = {"unchanged": "green", "changed": "yellow", "missing": "magenta", "failed": "red"}
    table = Table(title="Fleet Configuration Drift", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Status", width=9, no_wrap=True)
    table.add_column("Source", width=8, no_wrap=True)
    table.add_column("Baseline (UTC)", no_wrap=True)
    table.add_column("Compared (UTC)", no_wrap=True)
    table.add_column("Changes", width=11, justify="right")
    table.add_column("Note")
    for row in result["results"]:
        state = row["status"]
        table.add_row(
            row["device"], Text(state.upper(), style=f"bold {styles[state]}"),
            row["source"] or "—",
            row["baseline_captured_at"].replace("+00:00", "Z")[:20] or "—",
            row["compared_at"].replace("+00:00", "Z")[:20] or "—",
            f"+{row['added_lines']} / -{row['removed_lines']}" if state == "changed" else "—",
            row["error"],
        )
    console.print(table)
    counts = result["counts"]
    console.print(
        f"Total {counts['total']} | Unchanged {counts['unchanged']} | "
        f"Changed {counts['changed']} | Missing {counts['missing']} | Failed {counts['failed']}",
        markup=False,
    )
    if counts["changed"]:
        console.print(
            "Run snapshot compare DEVICE to inspect an individual unified diff.", style="dim"
        )


def render_fleet_baseline_creation(console: Console, result: dict) -> None:
    """Render compact results for bulk creation of missing baselines."""
    styles = {"created": "green", "existing": "cyan", "failed": "red"}
    table = Table(title="Fleet Baseline Creation", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Status", width=9, no_wrap=True)
    table.add_column("Source", width=8, no_wrap=True)
    table.add_column("Captured (UTC)", no_wrap=True)
    table.add_column("Revision", width=12, no_wrap=True)
    table.add_column("Note")
    for row in result["results"]:
        state = row["status"]
        table.add_row(
            row["device"], Text(state.upper(), style=f"bold {styles[state]}"),
            row["source"], row["captured_at"].replace("+00:00", "Z")[:20] or "—",
            row["revision"][:12] or "—", row["error"],
        )
    console.print(table)
    counts = result["counts"]
    console.print(
        f"Total {counts['total']} | Created {counts['created']} | "
        f"Existing {counts['existing']} | Failed {counts['failed']}",
        markup=False,
    )


def render_fleet_baseline_refresh(console: Console, result: dict) -> None:
    """Render fleet baseline replacements and first-time captures."""
    styles = {"refreshed": "green", "created": "cyan", "failed": "red"}
    table = Table(title="Fleet Baseline Refresh", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Status", width=10, no_wrap=True)
    table.add_column("Source", width=8, no_wrap=True)
    table.add_column("Previous (UTC)", no_wrap=True)
    table.add_column("Captured (UTC)", no_wrap=True)
    table.add_column("Revision", width=12, no_wrap=True)
    table.add_column("Note")
    for row in result["results"]:
        state = row["status"]
        table.add_row(
            row["device"], Text(state.upper(), style=f"bold {styles[state]}"),
            row["source"], row["previous_captured_at"].replace("+00:00", "Z")[:20] or "—",
            row["captured_at"].replace("+00:00", "Z")[:20] or "—",
            row["revision"][:12] or "—", row["error"],
        )
    console.print(table)
    counts = result["counts"]
    console.print(
        f"Total {counts['total']} | Refreshed {counts['refreshed']} | "
        f"Created {counts['created']} | Failed {counts['failed']}",
        markup=False,
    )


def render_baseline_status(console: Console, result: dict) -> None:
    """Render baseline age and the latest retained comparison status."""
    styles = {
        "unchanged": "green", "changed": "yellow", "missing": "magenta",
        "failed": "red", "not_checked": "dim",
    }
    table = Table(title="Configuration Baseline Status", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Baseline", width=9, no_wrap=True)
    table.add_column("Source", width=8, no_wrap=True)
    table.add_column("Age", width=8, justify="right", no_wrap=True)
    table.add_column("Last result", width=11, no_wrap=True)
    table.add_column("Last checked (UTC)", no_wrap=True)
    table.add_column("Changes", width=11, justify="right")
    table.add_column("Note")
    for row in result["devices"]:
        if not row["has_baseline"]:
            baseline_text = Text("MISSING", style="bold magenta")
            age = "—"
        elif row["stale"]:
            baseline_text = Text("STALE", style="bold yellow")
            age = f"{row['age_days']}d"
        else:
            baseline_text = Text("CURRENT", style="bold green")
            age = f"{row['age_days']}d"
        state = row["last_status"]
        changes = (
            f"+{row['added_lines']} / -{row['removed_lines']}"
            if state == "changed" else "—"
        )
        note = row["error"]
        if row["stale"] and not note:
            note = f"Older than {result['max_age_days']} days"
        table.add_row(
            row["device"], baseline_text, row["source"] or "—", age,
            Text(state.replace("_", " ").upper(), style=f"bold {styles[state]}"),
            row["last_checked_at"].replace("+00:00", "Z")[:20] or "—",
            changes, note,
        )
    console.print(table)
    counts = result["counts"]
    console.print(
        f"Devices {result['count']} | Baselines {counts['with_baseline']} | "
        f"Stale {counts['stale']} | Missing {counts['missing']} | "
        f"Changed {counts['changed']} | Failed {counts['failed']} | "
        f"Never checked {counts['not_checked']}",
        markup=False,
    )


def render_health(console: Console, results: list[dict]) -> None:
    """Render one or more parsed device health reports for terminal use."""
    styles = {"healthy": "green", "warning": "yellow", "critical": "red", "unknown": "dim"}
    # Explicit box style keeps contract output identical across Windows and POSIX.
    table = Table(
        title="Network Health", header_style=f"bold {PRIMARY_COLOR}", box=box.ROUNDED
    )
    table.add_column("Device", min_width=12, no_wrap=True)
    table.add_column("Health", width=8, no_wrap=True)
    table.add_column("Issues", width=9, no_wrap=True)
    table.add_column("Interfaces", width=10, no_wrap=True)
    table.add_column("Resources", width=10, no_wrap=True)
    table.add_column("Route", width=7, no_wrap=True)
    for result in results:
        metrics = result.get("metrics") or {}
        counts = result.get("counts") or {}
        overall = result.get("overall", "unknown") if result.get("status") == "success" else "unknown"
        total = metrics.get("interfaces_total")
        up = metrics.get("interfaces_up")
        interfaces = "—" if total is None else f"{up}/{total} up"
        cpu = metrics.get("cpu_five_minute_percent")
        memory = metrics.get("memory_free_percent")
        default_route = metrics.get("default_route")
        default_text = "—" if default_route is None else "yes" if default_route else "no"
        resources = (
            ("CPU —" if cpu is None else f"CPU {cpu}%") + "\n"
            + ("Mem —" if memory is None else f"Mem {memory:.1f}%")
        )
        table.add_row(
            str(result.get("device", "")),
            Text(overall.upper(), style=f"bold {styles[overall]}"),
            f"{counts.get('critical', 0)}C / {counts.get('warning', 0)}W",
            interfaces,
            resources,
            default_text,
        )
    console.print(table)

    for result in results:
        noteworthy = [check for check in result.get("checks", []) if check["severity"] in {"critical", "warning"}
                      or check["id"].endswith(("_unavailable", "_unparsed"))]
        if result.get("status") != "success":
            noteworthy.insert(0, {
                "severity": "critical", "summary": result.get("error") or "Health collection failed."
            })
        if not noteworthy:
            continue
        console.print()
        console.print(Text(f"{result.get('device', '')} findings", style=f"bold {PRIMARY_COLOR}"))
        for check in noteworthy:
            severity = check["severity"]
            line = Text("• ")
            line.append(severity.upper(), style=f"bold {styles.get(severity, 'dim')}")
            line.append("  " + check["summary"])
            console.print(line)


def render_vpn_status(console: Console, result: dict) -> None:
    """Render normalized FortiOS IPsec and SSL-VPN operational state."""
    console.print(Text(
        f"VPN Status: {result['device']}", style=f"bold {PRIMARY_COLOR}"
    ))
    if result["status"] in {"error", "unsupported"}:
        console.print(result.get("error") or "VPN status is unavailable.", style="red")
        return
    if result["has_active_vpn"] is True:
        console.print("Active VPN connectivity was observed.", style="green")
    elif result["has_active_vpn"] is False:
        console.print("No active VPN tunnels or sessions were observed.")
    else:
        console.print("Active VPN state could not be determined completely.", style="yellow")
    ipsec = result["ipsec"]
    ssl_vpn = result["ssl_vpn"]
    console.print(
        f"IPsec: {ipsec['active_count']} active of {ipsec['tunnel_count']} observed | "
        f"SSL-VPN: {ssl_vpn['active_session_count'] if ssl_vpn['active_session_count'] is not None else 'unknown'} active session(s)",
        markup=False,
    )
    if ipsec["tunnels"]:
        table = Table(header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("Tunnel", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Remote gateway", no_wrap=True)
        table.add_column("Selectors", no_wrap=True)
        table.add_column("RX packets", justify="right")
        table.add_column("TX packets", justify="right")
        for tunnel in ipsec["tunnels"]:
            selectors = (
                "—" if tunnel["selectors_total"] is None else
                f"{tunnel['selectors_up']}/{tunnel['selectors_total']} up"
            )
            table.add_row(
                tunnel["name"], tunnel["status"], tunnel["remote_gateway"] or "—",
                selectors,
                "—" if tunnel["rx_packets"] is None else str(tunnel["rx_packets"]),
                "—" if tunnel["tx_packets"] is None else str(tunnel["tx_packets"]),
            )
        console.print(table)
    for warning in result.get("warnings", []):
        console.print("• " + warning, style="yellow", markup=False)


def render_execution(console: Console, trace) -> None:
    """Render a compact timing and provenance footer below one completed result."""
    trace.finish()
    console.print("-" * min(console.width, 80), style="dim", markup=False)
    first = Text(style="dim")
    first.append(f"Completed in {trace.elapsed_seconds:.2f}s")
    first.append(" | OpenAI: ")
    first.append(trace.llm_model or "Unknown model" if trace.llm_used else "Not used", style=PRIMARY_COLOR)
    first.append(" | MCP: ")
    first.append("Local" if trace.mcp_used else "Not used", style=PRIMARY_COLOR)
    console.print(first)
    second = Text(style="dim")
    second.append("Data: ")
    second.append(" + ".join(trace.data_sources()), style=PRIMARY_COLOR)
    if trace.llm_used:
        second.append(f" | LLM calls: {trace.llm_calls}")
    if trace.mcp_used:
        second.append(f" | Tool calls: {len(trace.mcp_tools)}")
    console.print(second)
    if trace.path or trace.planning_seconds or trace.mcp_seconds or trace.llm_seconds:
        third = Text(style="dim")
        if trace.path:
            third.append("Path: ")
            third.append(trace.path, style=PRIMARY_COLOR)
        stages = []
        if trace.planning_seconds:
            stages.append(f"plan {trace.planning_seconds:.2f}s")
        if trace.mcp_seconds:
            stages.append(f"MCP {trace.mcp_seconds:.2f}s")
        if trace.llm_seconds:
            stages.append(f"OpenAI {trace.llm_seconds:.2f}s")
        if stages:
            third.append((" | " if trace.path else "") + "Stages: " + ", ".join(stages))
        if trace.input_tokens or trace.output_tokens:
            tokens = f"Tokens: {trace.input_tokens:,} in / {trace.output_tokens:,} out"
            if trace.cached_input_tokens:
                tokens += f" ({trace.cached_input_tokens:,} cached)"
            if trace.reasoning_tokens:
                tokens += f" / {trace.reasoning_tokens:,} reasoning"
            third.append(" | " + tokens)
        console.print(third)


def render_mac_scan(console: Console, result: dict) -> None:
    """Render compact per-device MAC collection results."""
    styles = {"success": "green", "partial": "yellow", "error": "red", "unsupported": "dim"}
    table = Table(title="MAC Observation Scan", header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Device", min_width=10, no_wrap=True)
    table.add_column("Status", width=11, no_wrap=True)
    table.add_column("MAC", justify="right")
    table.add_column("ARP", justify="right")
    table.add_column("Neighbors", justify="right")
    table.add_column("Note")
    for row in result["results"]:
        status = row["status"]
        table.add_row(
            row["device"], Text(status.upper(), style=f"bold {styles.get(status, 'dim')}"),
            str(row["mac_count"]), str(row["arp_count"]), str(row["neighbor_count"]),
            row.get("warning") or row.get("error") or "",
        )
    console.print(table)


def render_mac_location(console: Console, result: dict, troubleshooting: bool = False) -> None:
    """Render ranked MAC matches and any endpoint troubleshooting findings."""
    console.print(Text(f"MAC {result['mac']}", style=f"bold {PRIMARY_COLOR}"))
    console.print(
        f"{result['message']} Confidence: {result['confidence']}. "
        f"Observations complete: {'yes' if result['complete'] else 'no'}."
    )
    if result["ip_addresses"]:
        console.print("IPv4: " + ", ".join(result["ip_addresses"]), markup=False)
    if result["matches"]:
        table = Table(header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("Device", min_width=9, no_wrap=True)
        table.add_column("Interface", min_width=10, no_wrap=True)
        table.add_column("VLAN", width=5, no_wrap=True)
        table.add_column("Role", width=7, no_wrap=True)
        table.add_column("Type", width=7, no_wrap=True)
        table.add_column("Observed", no_wrap=True)
        likely = result.get("likely_endpoint")
        for row in result["matches"]:
            is_likely = likely is not None and all(
                row[key] == likely[key] for key in ("device_name", "interface", "vlan", "entry_type")
            )
            table.add_row(
                ("* " if is_likely else "  ") + row["device_name"], row["interface"],
                row["vlan"] or "—", row["role"], row["entry_type"],
                row["observed_at"].replace("+00:00", "Z")[:20],
            )
        console.print(table)
        console.print("* highest-ranked endpoint candidate", style="dim")
    if result["incomplete_devices"]:
        names = ", ".join(f"{row['device']} ({row['status']})" for row in result["incomplete_devices"])
        console.print("Incomplete devices: " + names, style="yellow", markup=False)
    if troubleshooting:
        if result["issues"]:
            console.print()
            console.print("Troubleshooting findings", style=f"bold {PRIMARY_COLOR}")
            for issue in result["issues"]:
                console.print("• " + issue, style="yellow", markup=False)
        else:
            console.print("No problems were identified in the current observations.", style="green")


def render_interface_macs(console: Console, result: dict) -> None:
    """Render learned MAC addresses for one device interface."""
    label = result["matched_interfaces"][0] if result["matched_interfaces"] else result["requested_interface"]
    console.print(Text(f"{result['device']} {label}", style=f"bold {PRIMARY_COLOR}"))
    console.print(result["message"], markup=False)
    if result["observations"]:
        table = Table(header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("MAC address", min_width=17, no_wrap=True)
        table.add_column("VLAN", width=6, no_wrap=True)
        table.add_column("Type", width=8, no_wrap=True)
        table.add_column("Role", width=8, no_wrap=True)
        table.add_column("IPv4 address")
        table.add_column("Observed", no_wrap=True)
        for row in result["observations"]:
            table.add_row(
                row["mac"], row["vlan"] or "—", row["entry_type"], row["role"],
                ", ".join(row["ip_addresses"]) or "—",
                row["observed_at"].replace("+00:00", "Z")[:20],
            )
        console.print(table)
    health = result.get("interface_health")
    if health:
        console.print(
            "Interface: "
            f"{health['status']}/{health['protocol']} | "
            f"input errors {health['input_errors']} | CRC {health['crc_errors']} | "
            f"output errors {health['output_errors']}",
            style="dim",
            markup=False,
        )
    if not result["complete"]:
        detail = f" ({result['error']})" if result.get("error") else ""
        console.print(
            f"Observation status: {result['scan_status']}{detail}", style="yellow", markup=False
        )


def render_device_macs(console: Console, result: dict) -> None:
    """Render the normalized MAC address table for one device."""
    console.print(Text(
        f"MAC Address Table: {result['device']}", style=f"bold {PRIMARY_COLOR}"
    ))
    console.print(result["message"], markup=False)
    if result["observations"]:
        table = Table(header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("VLAN", width=6, no_wrap=True)
        table.add_column("MAC address", min_width=17, no_wrap=True)
        table.add_column("Interface", min_width=10, no_wrap=True)
        table.add_column("Type", width=8, no_wrap=True)
        table.add_column("Role", width=8, no_wrap=True)
        table.add_column("IPv4 address")
        table.add_column("Observed", no_wrap=True)
        for row in result["observations"]:
            table.add_row(
                row["vlan"] or "—", row["mac"], row["interface"],
                row["entry_type"], row["role"],
                ", ".join(row["ip_addresses"]) or "—",
                row["observed_at"].replace("+00:00", "Z")[:20],
            )
        console.print(table)
    if not result["complete"]:
        detail = f" ({result['error']})" if result.get("error") else ""
        console.print(
            f"Observation status: {result['scan_status']}{detail}",
            style="yellow", markup=False,
        )


def render_device_arps(console: Console, result: dict) -> None:
    """Render the normalized ARP table for one device."""
    console.print(Text(
        f"ARP Table: {result['device']}", style=f"bold {PRIMARY_COLOR}"
    ))
    console.print(result["message"], markup=False)
    if result["observations"]:
        table = Table(header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("IPv4 address", min_width=15, no_wrap=True)
        table.add_column("MAC address", min_width=17, no_wrap=True)
        table.add_column("Interface", min_width=10, no_wrap=True)
        table.add_column("VRF", min_width=7, no_wrap=True)
        table.add_column("Observed", no_wrap=True)
        for row in result["observations"]:
            table.add_row(
                row["ip"], row["mac"], row["interface"] or "—",
                row["vrf"] or "default",
                row["observed_at"].replace("+00:00", "Z")[:20],
            )
        console.print(table)
    if not result["complete"]:
        detail = f" ({result['error']})" if result.get("error") else ""
        console.print(
            f"Observation status: {result['scan_status']}{detail}",
            style="yellow", markup=False,
        )


def render_route_trace(console: Console, result: dict) -> None:
    """Render a parsed OSPF route trace and inventory correlation."""
    console.print(Text(
        f"OSPF route trace: {result['device']} → {result['destination']}",
        style=f"bold {PRIMARY_COLOR}",
    ))
    if result["status"] != "success":
        console.print(result.get("error") or "Route trace failed.", style="red", markup=False)
        return
    if not result["route_found"]:
        console.print("The destination is not present in the selected routing table.", style="yellow")
        return
    route = result["route"]
    console.print(
        f"Route: {route.get('prefix') or result['destination']} | "
        f"protocol {route.get('protocol') or 'unknown'} | "
        f"distance {route.get('distance') if route.get('distance') is not None else '—'} | "
        f"metric {route.get('metric') if route.get('metric') is not None else '—'}",
        markup=False,
    )
    table = Table(header_style=f"bold {PRIMARY_COLOR}")
    table.add_column("Next hop", no_wrap=True)
    table.add_column("Outgoing interface", no_wrap=True)
    table.add_column("Neighbor router ID", no_wrap=True)
    table.add_column("Inventory device", no_wrap=True)
    table.add_column("State", no_wrap=True)
    for hop in result["next_hops"]:
        table.add_row(
            hop["address"], hop["interface"] or "—", hop.get("neighbor_router_id") or "—",
            hop.get("device") or "unresolved", hop.get("neighbor_state") or "—",
        )
    console.print(table)
    advertiser = result.get("advertising_device") or "unresolved"
    router_id = result.get("advertising_router_id") or "unresolved"
    console.print(
        f"Advertising device: {advertiser} | Router ID: {router_id} | "
        f"Confidence: {result['confidence']} | Complete: {'yes' if result['complete'] else 'no'}",
        markup=False,
    )
    if result["incomplete_devices"]:
        devices = ", ".join(row["device"] for row in result["incomplete_devices"])
        console.print("Incomplete interface checks: " + devices, style="yellow", markup=False)
    for warning in result.get("warnings", []):
        console.print("• " + warning, style="yellow", markup=False)
    if result["evidence"]:
        console.print()
        console.print("Route evidence", style=f"bold {PRIMARY_COLOR}")
        for line in result["evidence"]:
            console.print(line, style=CONFIG_COLOR, markup=False)


def render_topology(console: Console, result: dict) -> None:
    """Render correlated topology links and explicit coverage gaps."""
    console.print(Text(
        f"Network Topology: {result['target']}", style=f"bold {PRIMARY_COLOR}"
    ))
    counts = result["counts"]
    console.print(
        f"Nodes {counts['nodes']} | Links {counts['links']} | "
        f"Bidirectional {counts['bidirectional']} | One-sided {counts['one_sided']} | "
        f"Unresolved {counts['unresolved']} | Incomplete devices {counts['incomplete_devices']}",
        markup=False,
    )
    if result["links"]:
        table = Table(title="Resolved Links", header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("Device A", min_width=9, no_wrap=True)
        table.add_column("Interface A", min_width=9, no_wrap=True)
        table.add_column("Link", width=3, justify="center")
        table.add_column("Device B", min_width=9, no_wrap=True)
        table.add_column("Interface B", min_width=9, no_wrap=True)
        table.add_column("Protocol", no_wrap=True)
        table.add_column("Confidence", no_wrap=True)
        for link in result["links"]:
            table.add_row(
                link["a"]["device"], link["a"]["interface"],
                "↔" if link["bidirectional"] else "→",
                link["b"]["device"], link["b"]["interface"] or "—",
                "/".join(link["protocols"]).upper(), link["confidence"],
            )
        console.print(table)
    else:
        console.print("No inventory-correlated links were found.", style="dim")
    if result["unresolved_neighbors"]:
        table = Table(title="Unresolved Neighbors", header_style="bold yellow")
        table.add_column("Source", no_wrap=True)
        table.add_column("Local interface", no_wrap=True)
        table.add_column("Neighbor")
        table.add_column("Address", no_wrap=True)
        table.add_column("Protocol", no_wrap=True)
        table.add_column("Reason")
        for row in result["unresolved_neighbors"]:
            table.add_row(
                row["source"], row["interface"], row["neighbor"],
                row["neighbor_address"] or "—", row["protocol"].upper(), row["reason"],
            )
        console.print(table)
    if result["incomplete_devices"]:
        table = Table(title="Incomplete Collection", header_style="bold red")
        table.add_column("Device", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Last observation", no_wrap=True)
        table.add_column("Error")
        for row in result["incomplete_devices"]:
            table.add_row(
                row["device"], row["status"].upper(),
                row["observations_at"].replace("+00:00", "Z")[:20] or "—",
                row["error"],
            )
        console.print(table)


def render_topology_diagram(console: Console, result: dict) -> None:
    """Render the dependency-free text topology diagram with NERD colors."""
    suffix = f" · {result['location_filter']}" if result["location_filter"] else ""
    console.print(Text(
        f"Network Topology Diagram: {result['target']}{suffix}",
        style=f"bold {PRIMARY_COLOR}",
    ))
    for line in result["diagram"].splitlines():
        if "unresolved" in line or "-?.." in line:
            style = "yellow"
        elif "--->" in line:
            style = CONFIG_COLOR
        elif "no correlated links" in line:
            style = "dim"
        else:
            style = PRIMARY_COLOR
        console.print(line, style=style, markup=False, highlight=False)
    counts = result["counts"]
    console.print(
        f"Nodes {counts['nodes']} | Links {counts['links']} | "
        f"Unresolved {counts['unresolved']} | Incomplete {counts['incomplete_devices']}",
        style="dim", markup=False,
    )


def render_mac_path(console: Console, result: dict) -> None:
    """Render an inferred MAC path, endpoint attachment, and confidence gaps."""
    console.print(Text(f"MAC Path: {result['mac']}", style=f"bold {PRIMARY_COLOR}"))
    if result["hops"]:
        table = Table(title="Observed Path", header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("Hop", justify="right")
        table.add_column("From device", no_wrap=True)
        table.add_column("From interface", no_wrap=True)
        table.add_column("Link", width=3, justify="center")
        table.add_column("To device", no_wrap=True)
        table.add_column("To interface", no_wrap=True)
        table.add_column("Protocol", no_wrap=True)
        table.add_column("Confidence", no_wrap=True)
        for hop in result["hops"]:
            table.add_row(
                str(hop["sequence"]), hop["from_device"], hop["from_interface"],
                "↔" if hop["bidirectional"] else "→", hop["to_device"],
                hop["to_interface"] or "—", "/".join(hop["protocols"]).upper(),
                hop["confidence"],
            )
        console.print(table)
    endpoint = result.get("endpoint")
    if endpoint:
        ips = ", ".join(endpoint.get("ip_addresses", [])) or "—"
        console.print(
            f"Endpoint: {endpoint['device_name']} {endpoint['interface']} | "
            f"VLAN {endpoint['vlan'] or '—'} | IP {ips}",
            style=CONFIG_COLOR, markup=False,
        )
    elif not result["found"]:
        console.print("The MAC was not found in current observations.", style="yellow")
    else:
        console.print("A unique dynamic access-port endpoint was not found.", style="yellow")
    console.print(
        f"Source: {result['source_device'] or 'unresolved'} | "
        f"Confidence: {result['confidence']} | Complete: {'yes' if result['complete'] else 'no'}",
        markup=False,
    )
    if result["alternative_paths"]:
        console.print("Alternative paths", style=f"bold {PRIMARY_COLOR}")
        for path in result["alternative_paths"]:
            console.print(" → ".join(path), style="yellow", markup=False)
    if result["unresolved_hops"]:
        table = Table(title="Unresolved MAC-Bearing Uplinks", header_style="bold yellow")
        table.add_column("Device", no_wrap=True)
        table.add_column("Interface", no_wrap=True)
        table.add_column("VLAN", no_wrap=True)
        table.add_column("Observed neighbor")
        table.add_column("Reason")
        for row in result["unresolved_hops"]:
            table.add_row(
                row["device"], row["interface"], row["vlan"] or "—",
                ", ".join(row["neighbors"]) or "—", row["reason"],
            )
        console.print(table)
    if result["incomplete_devices"]:
        table = Table(title="Incomplete Path Data", header_style="bold red")
        table.add_column("Source", no_wrap=True)
        table.add_column("Device", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Error")
        for row in result["incomplete_devices"]:
            table.add_row(
                row["source"].upper(), row["device"], row["status"].upper(),
                row.get("error") or "",
            )
        console.print(table)
    for warning in result["warnings"]:
        console.print("• " + warning, style="yellow", markup=False)


def render_endpoint(console: Console, result: dict) -> None:
    """Render inventory or observed endpoint resolution."""
    console.print(Text(
        f"Endpoint: {result['normalized_identifier']}", style=f"bold {PRIMARY_COLOR}"
    ))
    if result["resolution"] == "inventory":
        table = Table(title="Inventory Match", header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("Device", no_wrap=True)
        table.add_column("Hostname", no_wrap=True)
        table.add_column("Management address", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("Location")
        for device in result["inventory_devices"]:
            location = ", ".join(filter(None, (
                device.get("location"), device.get("city"), device.get("state"),
            )))
            table.add_row(
                device["name"], device.get("device_hostname") or "—", device["host"],
                device.get("device_type") or "—", location or "—",
            )
        console.print(table)
    elif result["endpoints"]:
        table = Table(title="Observed Attachment", header_style=f"bold {PRIMARY_COLOR}")
        table.add_column("IPv4", no_wrap=True)
        table.add_column("MAC", no_wrap=True)
        table.add_column("Device", no_wrap=True)
        table.add_column("Interface", no_wrap=True)
        table.add_column("VLAN", no_wrap=True)
        table.add_column("Confidence", no_wrap=True)
        table.add_column("Path")
        for path in result["endpoints"]:
            endpoint = path.get("endpoint") or {}
            ips = endpoint.get("ip_addresses") or ([result["ip_address"]] if result["ip_address"] else [])
            table.add_row(
                ", ".join(ips) or "—", path["mac"],
                endpoint.get("device_name") or "unresolved",
                endpoint.get("interface") or "—", endpoint.get("vlan") or "—",
                path.get("confidence", "none"), " → ".join(path.get("path_devices", [])) or "—",
            )
        console.print(table)
    else:
        console.print("No endpoint attachment was resolved.", style="yellow")
    console.print(
        f"Type: {result['identifier_type']} | Complete: "
        f"{'yes' if result['complete'] else 'no'} | Refreshed: "
        f"{'yes' if result['refreshed'] else 'no'}",
        style="dim", markup=False,
    )
    if result["incomplete_devices"]:
        names = ", ".join(
            f"{row['device']} ({row['status']})" for row in result["incomplete_devices"]
        )
        console.print("Incomplete devices: " + names, style="yellow", markup=False)
    for warning in result["warnings"]:
        console.print("• " + warning, style="yellow", markup=False)
