import argparse
import asyncio
import json
import logging
import os
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .execution import ExecutionTrace
from .inventory import Inventory, InventoryError
from .settings import default_database


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="NERD MCP: vendor-agnostic Network Engineering Reconnaissance & Discovery"
    )
    parser.add_argument("--db", default=default_database(),
                        help="Inventory database path (also NERD_MCP_DB)")
    parser.add_argument("--no-footer", action="store_true", help="Hide execution timing and provenance")
    sub = parser.add_subparsers(dest="command", required=True)
    devices = sub.add_parser("devices", help="Manage and search devices locally").add_subparsers(dest="action", required=True)
    imp = devices.add_parser("import", help="Import an Excel-compatible UTF-8 CSV")
    imp.add_argument("file", help="UTF-8 CSV or Excel .xlsx inventory file")
    imp.add_argument("--update", action="store_true")
    devices.add_parser("list")
    devices.add_parser("remove").add_argument("name")
    devices.add_parser("show").add_argument("name")
    search = devices.add_parser("search", help="Search inventory metadata")
    for field in ("city", "state", "location", "device-type", "hostname", "country",
                  "serial-number", "model", "vendor", "platform"):
        search.add_argument(f"--{field}", default="")
    refresh = devices.add_parser("refresh", help="Collect hostname, model, serial and location over SSH")
    refresh.add_argument("target", help="Device name or all")
    refresh.add_argument("--mock", action="store_true", help="Use simulated device output")
    host_key = devices.add_parser(
        "host-key", help="Manage verified SSH host keys"
    ).add_subparsers(dest="host_key_action", required=True)
    host_key.add_parser("enroll", help="Retrieve and confirm a device host key").add_argument("name")
    credentials = sub.add_parser("credentials", help="Manage saved Windows SSH credentials").add_subparsers(dest="action", required=True)
    for action in ("set", "status", "remove"):
        credentials.add_parser(action).add_argument("profile", nargs="?", default="default")
    for name in ("serve", "chat", "inspect"):
        action = sub.add_parser(name)
        action.add_argument("--mock", action="store_true", help="Return simulated device data without SSH")
        if name == "chat":
            action.add_argument(
                "--tool-transport", choices=("local", "mcp"), default="local",
                help="Run tools in process or through the optional MCP stdio adapter",
            )
            action.add_argument(
                "--enable-writes", action="store_true",
                help="Opt in to experimental CLI device configuration writes",
            )
        elif name == "inspect":
            action.add_argument("device")
            action.add_argument("operation", choices=["get_device_info", "get_device_facts", "get_interfaces", "get_vlans", "get_routes", "get_neighbors", "get_configuration", "get_health", "get_ospf_status", "get_bgp_status", "get_bgp_routes", "get_vpn_status"])
            action.add_argument("--source", choices=["running", "startup"], default="running")
            action.add_argument("--cursor", type=int, default=0)
            action.add_argument("--revision", default="")
    config = sub.add_parser("config", help="Print or save a complete sanitized Cisco configuration")
    config.add_argument("device")
    config.add_argument("--source", choices=["running", "startup"], default="running")
    config.add_argument("--output", help="Write the sanitized configuration to this file")
    config.add_argument("--mock", action="store_true", help="Return simulated device data without SSH")
    snapshot = sub.add_parser(
        "snapshot", help="Manage one sanitized configuration baseline per device"
    ).add_subparsers(dest="snapshot_action", required=True)
    snapshot_create = snapshot.add_parser("create", help="Capture a new approved baseline")
    snapshot_create.add_argument("device")
    snapshot_create.add_argument("--source", choices=["running", "startup"], default="running")
    snapshot_create.add_argument(
        "--replace", action="store_true", help="Replace the device's existing baseline"
    )
    snapshot_create.add_argument("--mock", action="store_true", help="Use simulated device output")
    snapshot_create.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_create.add_argument(
        "--workers", type=int, default=4, help="Concurrent device limit for target all (1-16)"
    )
    snapshot_refresh = snapshot.add_parser(
        "refresh", help="Refresh baselines for every inventoried device"
    )
    snapshot_refresh.add_argument("target", choices=["all"])
    snapshot_refresh.add_argument(
        "--source", choices=["running", "startup"], default=None,
        help="Override the source for every device (default: preserve existing sources)",
    )
    snapshot_refresh.add_argument(
        "--workers", type=int, default=4, help="Concurrent device limit (1-16)"
    )
    snapshot_refresh.add_argument("--mock", action="store_true", help="Use simulated device output")
    snapshot_refresh.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_refresh.add_argument(
        "--yes", action="store_true", help="Confirm replacement without an interactive prompt"
    )
    snapshot_list = snapshot.add_parser("list", help="List stored baseline metadata")
    snapshot_list.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_status = snapshot.add_parser(
        "status", help="Show baseline age and latest comparison status"
    )
    snapshot_status.add_argument(
        "--max-age-days", type=int, default=30, help="Mark older baselines stale (default: 30)"
    )
    snapshot_status.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_show = snapshot.add_parser("show", help="Print a stored sanitized baseline")
    snapshot_show.add_argument("device")
    snapshot_show.add_argument("--output", help="Write the sanitized baseline to this file")
    snapshot_show.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_compare = snapshot.add_parser(
        "compare", help="Compare a stored baseline with the current device configuration"
    )
    snapshot_compare.add_argument("device", help="Device name or all")
    snapshot_compare.add_argument("--output", help="Write a single-device unified diff to this file")
    snapshot_compare.add_argument(
        "--workers", type=int, default=4, help="Concurrent device limit for target all (1-16)"
    )
    snapshot_compare.add_argument("--mock", action="store_true", help="Use simulated device output")
    snapshot_compare.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    snapshot_remove = snapshot.add_parser("remove", help="Delete a stored baseline")
    snapshot_remove.add_argument("device")
    change = sub.add_parser(
        "change", help="Plan, approve, apply, verify, save, and audit configuration changes"
    ).add_subparsers(dest="change_action", required=True)
    change_plan = change.add_parser("plan", help="Prepare and store a validated change plan")
    targets = change_plan.add_mutually_exclusive_group(required=True)
    targets.add_argument("--device")
    targets.add_argument("--devices", nargs="+")
    request_source = change_plan.add_mutually_exclusive_group(required=True)
    request_source.add_argument("--request", help="Natural language or strict JSON request")
    request_source.add_argument("--file", type=Path, help="Strict JSON operation file")
    change_plan.add_argument("--mock", action="store_true", help="Plan against simulated preflight data")
    change_plan.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    for action_name in ("show", "status", "apply", "save", "rollback"):
        action = change.add_parser(action_name)
        action.add_argument("change_id")
        action.add_argument("--json", action="store_true", help="Print machine-readable JSON")
        if action_name in {"apply", "save", "rollback"}:
            action.add_argument(
                "--enable-writes", action="store_true",
                help="Opt in to experimental device configuration writes",
            )
    change_history = change.add_parser("history")
    change_history.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    change_purge = change.add_parser("purge", help="Delete audit records older than an ISO date")
    change_purge.add_argument("--before", required=True)
    change_purge.add_argument("--yes", action="store_true")
    health = sub.add_parser("health", help="Run parsed read-only health checks")
    health.add_argument("target", help="Device name or all")
    health.add_argument("--mock", action="store_true", help="Use simulated device output")
    health.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    vpn = sub.add_parser("vpn", help="Inspect current VPN operational state").add_subparsers(
        dest="vpn_action", required=True
    )
    parser.add_argument("--version", action="version", version=f"nerd-mcp {__version__}")
    vpn_status = vpn.add_parser("status", help="Read FortiOS IPsec and SSL-VPN status")
    vpn_status.add_argument("device")
    vpn_status.add_argument("--mock", action="store_true", help="Use simulated device output")
    vpn_status.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    mac = sub.add_parser("mac", help="Collect, locate, and troubleshoot MAC addresses").add_subparsers(
        dest="mac_action", required=True
    )
    mac_scan = mac.add_parser("scan", help="Refresh MAC observations from one device or all")
    mac_scan.add_argument("target", help="Device name or all")
    for action in (mac_scan,):
        action.add_argument("--workers", type=int, default=4, help="Concurrent device limit (1-16)")
        action.add_argument("--mock", action="store_true", help="Use simulated device output")
        action.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    for name in ("locate", "troubleshoot"):
        action = mac.add_parser(
            name,
            help=(
                f"{name.title()} one endpoint by MAC address; collect automatically "
                "when observations are missing or stale"
            ),
        )
        action.add_argument("mac_address")
        action.add_argument("--max-age", type=int, default=15, help="Maximum observation age in minutes")
        action.add_argument(
            "--refresh", action="store_true",
            help="Force a scan of all devices even when cached observations are current",
        )
        action.add_argument("--workers", type=int, default=4, help="Concurrent device limit (1-16)")
        action.add_argument("--mock", action="store_true", help="Use simulated device output")
        action.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    mac_port = mac.add_parser(
        "port",
        help=(
            "List learned MAC addresses on one device interface; collect "
            "automatically when observations are missing or stale"
        ),
    )
    mac_port.add_argument("device")
    mac_port.add_argument("interface")
    mac_port.add_argument("--max-age", type=int, default=15, help="Maximum observation age in minutes")
    mac_port.add_argument(
        "--refresh", action="store_true",
        help="Force a scan of this device even when cached observations are current",
    )
    mac_port.add_argument("--workers", type=int, default=1, help="Concurrent device limit (1-16)")
    mac_port.add_argument("--mock", action="store_true", help="Use simulated device output")
    mac_port.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    mac_table = mac.add_parser(
        "table",
        help=(
            "List the normalized MAC table for one device; collect automatically "
            "when observations are missing or stale"
        ),
    )
    mac_table.add_argument("device")
    mac_table.add_argument("--max-age", type=int, default=15, help="Maximum observation age in minutes")
    mac_table.add_argument(
        "--refresh", action="store_true",
        help="Force a scan of this device even when cached observations are current",
    )
    mac_table.add_argument("--workers", type=int, default=1, help="Concurrent device limit (1-16)")
    mac_table.add_argument("--mock", action="store_true", help="Use simulated device output")
    mac_table.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    arp = sub.add_parser("arp", help="Inspect normalized ARP observations").add_subparsers(
        dest="arp_action", required=True
    )
    arp_table = arp.add_parser(
        "table",
        help=(
            "List the normalized ARP table for one device; collect automatically "
            "when observations are missing or stale"
        ),
    )
    arp_table.add_argument("device")
    arp_table.add_argument("--max-age", type=int, default=15, help="Maximum observation age in minutes")
    arp_table.add_argument(
        "--refresh", action="store_true",
        help="Force a scan of this device even when cached observations are current",
    )
    arp_table.add_argument("--workers", type=int, default=1, help="Concurrent device limit (1-16)")
    arp_table.add_argument("--mock", action="store_true", help="Use simulated device output")
    arp_table.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    route = sub.add_parser("route", help="Trace exact routes and resolve routing peers").add_subparsers(
        dest="route_action", required=True
    )
    route_trace = route.add_parser("trace", help="Trace an OSPF route from one Cisco router")
    route_trace.add_argument("device", help="Inventoried router whose routing table is examined")
    route_trace.add_argument("destination", help="Exact unicast IPv4 destination")
    route_trace.add_argument("--workers", type=int, default=4, help="Concurrent inventory checks (1-16)")
    route_trace.add_argument("--mock", action="store_true", help="Use simulated device output")
    route_trace.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    topology = sub.add_parser(
        "topology", help="Discover and inspect inventory-correlated network links"
    ).add_subparsers(dest="topology_action", required=True)
    topology_discover = topology.add_parser(
        "discover", help="Refresh CDP/LLDP observations and build topology"
    )
    topology_discover.add_argument("target", nargs="?", default="all", help="Device name or all")
    topology_discover.add_argument("--workers", type=int, default=4, help="Concurrent device limit (1-16)")
    topology_discover.add_argument("--max-age", type=int, default=60, help="Freshness limit in minutes")
    topology_discover.add_argument("--mock", action="store_true", help="Use simulated device output")
    topology_discover.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    topology_show = topology.add_parser("show", help="Build topology from cached observations only")
    topology_show.add_argument("target", nargs="?", default="all", help="Device name or all")
    topology_show.add_argument("--max-age", type=int, default=60, help="Freshness limit in minutes")
    topology_show.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    topology_diagram = topology.add_parser(
        "diagram", help="Render cached topology as terminal text or Mermaid"
    )
    topology_diagram.add_argument("target", nargs="?", default="all", help="Device name or all")
    topology_diagram.add_argument(
        "--location", default="", help="Filter by inventory location and include boundary neighbors"
    )
    topology_diagram.add_argument("--max-age", type=int, default=60, help="Freshness limit in minutes")
    topology_diagram.add_argument(
        "--format", dest="output_format", choices=["text", "mermaid"], default="text"
    )
    topology_diagram.add_argument("--output", help="Write the diagram to a UTF-8 file")
    topology_diagram.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    path = sub.add_parser(
        "path", help="Trace endpoint paths through current MAC and topology observations"
    ).add_subparsers(dest="path_action", required=True)
    path_mac = path.add_parser("mac", help="Trace a MAC-bearing path to its access port")
    path_mac.add_argument("mac_address")
    path_mac.add_argument(
        "--from", dest="source_device", default="", help="Optional inventoried starting device"
    )
    path_mac.add_argument("--max-age", type=int, default=15, help="Freshness limit in minutes")
    path_mac.add_argument("--refresh", action="store_true", help="Refresh all observations before tracing")
    path_mac.add_argument("--workers", type=int, default=4, help="Concurrent device limit (1-16)")
    path_mac.add_argument("--mock", action="store_true", help="Use simulated device output")
    path_mac.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    endpoint = sub.add_parser(
        "endpoint", help="Locate an endpoint by IPv4 address, MAC, or inventoried hostname"
    ).add_subparsers(dest="endpoint_action", required=True)
    endpoint_locate = endpoint.add_parser(
        "locate", help="Resolve and trace an endpoint to its observed attachment"
    )
    endpoint_locate.add_argument("identifier", help="IPv4 address, unicast MAC, or hostname")
    endpoint_locate.add_argument(
        "--from", dest="source_device", default="", help="Optional inventoried starting device"
    )
    endpoint_locate.add_argument("--max-age", type=int, default=15, help="Freshness limit in minutes")
    endpoint_locate.add_argument("--refresh", action="store_true", help="Refresh all observations first")
    endpoint_locate.add_argument("--workers", type=int, default=4, help="Concurrent device limit (1-16)")
    endpoint_locate.add_argument("--mock", action="store_true", help="Use simulated device output")
    endpoint_locate.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)
    # Suppress third-party wire logging, which can include device output.
    logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
    logger = logging.getLogger("nerd_mcp.operations")
    logger.setLevel(logging.INFO)
    # Rich owns the interactive progress line; operation logs would corrupt it.
    logger.disabled = args.command == "chat"
    inventory = Inventory(args.db)
    from .bootstrap import build_application
    application = build_application(
        inventory, bool(getattr(args, "mock", False)),
        pooled=args.command in {"serve", "chat"},
    )
    execution = None if args.command in {"serve", "chat"} else ExecutionTrace()
    try:
        if args.command == "credentials":
            execution.local_system_used = True
            from .credentials import normalize_profile, remove_saved, resolve_credentials, save_saved
            profile = normalize_profile(args.profile)
            if args.action == "set":
                import getpass
                import warnings
                if not sys.stdin.isatty():
                    raise InventoryError(
                        "Run credentials set in an interactive PowerShell window; do not pipe passwords."
                    )
                print(
                    f"Save or replace profile '{profile}' in Windows Credential Manager "
                    "for this Windows account."
                )
                try:
                    username = input("Device username: ").strip()
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", getpass.GetPassWarning)
                        password = getpass.getpass("Device password (hidden): ")
                        confirmation = getpass.getpass("Confirm password (hidden): ")
                except (EOFError, getpass.GetPassWarning):
                    raise InventoryError(
                        "Hidden credential entry unavailable. Use an interactive Windows PowerShell terminal."
                    ) from None
                if password != confirmation:
                    raise InventoryError("Passwords do not match. Nothing saved.")
                save_saved(profile, username, password)
                print(
                    f"Saved profile '{profile}'. Password was not written to project "
                    "files or Codex configuration."
                )
            elif args.action == "remove":
                remove_saved(profile)
                print(f"Removed saved profile '{profile}'. Environment credentials, if set, still apply.")
            else:
                _username, _password, source = resolve_credentials(profile)
                print(f"Profile '{profile}': available via {source}. SSH login has not been tested.")
        elif args.command == "devices":
            execution.local_inventory_used = True
            if args.action == "import":
                counts = inventory.import_file(args.file, args.update)
                print(", ".join(f"{key}: {value}" for key, value in counts.items()))
            elif args.action == "list":
                print(json.dumps([asdict(d) for d in inventory.list()], indent=2))
            elif args.action == "show":
                print(json.dumps(asdict(inventory.get(args.name)), indent=2))
            elif args.action == "search":
                print(json.dumps([asdict(d) for d in inventory.search(
                    city=args.city, state=args.state, location=args.location,
                    device_type=args.device_type, hostname=args.hostname,
                    country=args.country, serial_number=args.serial_number,
                    model=args.model, vendor=args.vendor, platform=args.platform,
                )], indent=2))
            elif args.action == "refresh":
                service = application.inventory_refresh
                try:
                    results = service.refresh(args.target)
                finally:
                    if service.successful_discoveries:
                        if args.mock:
                            execution.mock_used = True
                        else:
                            execution.live_ssh_used = True
                print(json.dumps(results, indent=2))
                return 1 if any(result["status"] != "success" for result in results) else 0
            elif args.action == "host-key":
                from .hostkeys import (
                    commit_host_key_enrollment,
                    prepare_host_key_enrollment,
                )
                proposal = prepare_host_key_enrollment(inventory, args.name)
                if proposal.status == "already_enrolled":
                    result = proposal.result()
                else:
                    prompt = (
                        f"Device: {proposal.device} ({proposal.host}:{proposal.port})\n"
                        f"Algorithm: {proposal.algorithm}\n"
                        f"SHA-256 fingerprint: {proposal.fingerprint}\n"
                        "Verify this fingerprint using the device console or another trusted source.\n"
                        "Type yes to enroll this host key: "
                    )
                    try:
                        approved = input(prompt).strip().casefold() == "yes"
                    except EOFError:
                        approved = False
                    if not approved:
                        raise InventoryError(
                            "SSH host key was not enrolled; confirmation requires typing yes."
                        )
                    result = commit_host_key_enrollment(proposal)
                execution.live_ssh_used = True
                if result["status"] == "already_enrolled":
                    print(
                        f"{result['device']} host key is already enrolled: "
                        f"{result['algorithm']} {result['fingerprint']}"
                    )
                else:
                    print(
                        f"Enrolled {result['device']} host key in {result['known_hosts']}: "
                        f"{result['algorithm']} {result['fingerprint']}"
                    )
            elif not inventory.remove(args.name):
                raise InventoryError("Device not found.")
            else:
                print("Device removed.")
        elif args.command == "serve":
            try:
                from .server import build_server
            except ImportError as exc:
                raise ValueError(
                    "MCP server support is not installed; install nerd-mcp-assistant[mcp]."
                ) from exc
            build_server(application=application).run(transport="stdio")
        elif args.command == "chat":
            from .chat import local_session, run_chat

            async def run_selected_chat():
                options = {
                    "baseline_service": application.baseline_writes,
                    "application": application,
                    "write_enabled": args.enable_writes,
                }
                if args.tool_transport == "mcp":
                    async with local_session(inventory.path, args.mock) as executor:
                        return await run_chat(
                            inventory.path, args.mock, not args.no_footer,
                            executor=executor, **options,
                        )
                return await run_chat(
                    inventory.path, args.mock, not args.no_footer, **options,
                )

            asyncio.run(run_selected_chat())
        elif args.command == "change":
            execution.local_inventory_used = True
            from .application.changes import parse_structured_request, translate_request

            if args.change_action == "plan":
                devices = tuple(args.devices or (args.device,))
                if args.file is not None:
                    request = parse_structured_request(args.file, devices)
                else:
                    try:
                        request = parse_structured_request(args.request, devices)
                    except InventoryError as structured_error:
                        if args.request.lstrip().startswith(("{", "[")):
                            raise structured_error
                        model = os.getenv("OPENAI_MODEL") or os.getenv("NERD_OPENAI_MODEL")
                        if not model:
                            raise InventoryError(
                                "Natural-language planning requires OPENAI_MODEL and OPENAI_API_KEY; "
                                "alternatively pass a strict JSON request or --file."
                            )
                        request = translate_request(args.request, devices, model)
                result = application.change_planning.plan(request)
                execution.mock_used = args.mock
                execution.live_ssh_used = not args.mock
            elif args.change_action in {"show", "status"}:
                result = application.changes.get(args.change_id)
            elif args.change_action == "history":
                result = {"changes": application.changes.history()}
            elif args.change_action == "purge":
                if not args.yes:
                    if not sys.stdin.isatty():
                        raise InventoryError("Non-interactive audit purge requires --yes.")
                    answer = input(f"Type PURGE to delete change records before {args.before}: ")
                    if answer.strip() != "PURGE":
                        raise InventoryError("Change-history purge cancelled.")
                result = {"deleted": application.change_writes.purge(args.before)}
            else:
                if not args.enable_writes:
                    raise InventoryError(
                        "Device writes are disabled by default. Re-run this command with "
                        "--enable-writes after reviewing the experimental write-safety documentation."
                    )
                plan = application.changes.get(args.change_id)
                expected = "prepared" if args.change_action == "apply" else "applied_pending_save"
                if plan["state"] != expected:
                    raise InventoryError(
                        f"Change is {plan['state']}; it must be {expected} first."
                    )
                phrase = f"{args.change_action.upper()} {plan['change_id']}"
                if not sys.stdin.isatty():
                    raise InventoryError(
                        f"Configuration {args.change_action} requires an interactive terminal."
                    )
                if args.json:
                    print(json.dumps(plan, indent=2))
                else:
                    from rich.console import Console
                    from .presentation import render_change_plan
                    render_change_plan(Console(), plan)
                answer = input(f"Type {phrase} to continue: ")
                if answer.strip() != phrase:
                    raise InventoryError(f"Configuration {args.change_action} cancelled.")
                authorization = application.change_writes.authorize(
                    args.change_id, args.change_action
                )
                method = getattr(application.change_writes, args.change_action)
                result = method(args.change_id, authorization=authorization)
                execution.live_ssh_used = True
            if getattr(args, "json", False):
                print(json.dumps(result, indent=2))
            elif args.change_action == "history":
                for row in result["changes"]:
                    print(f"{row['change_id']}  {row['state']}  {row['created_at']}")
            elif args.change_action in {"plan", "show", "status"}:
                from rich.console import Console
                from .presentation import render_change_plan
                render_change_plan(Console(), result)
            else:
                from rich.console import Console
                from .presentation import render_change_result
                render_change_result(Console(), result)
            return 0 if result.get("state") != "failed" else 1
        elif args.command == "health":
            execution.local_inventory_used = True
            service = application.fleet_health
            results = service.check(args.target)
            if any(result["status"] == "success" for result in results):
                if args.mock:
                    execution.mock_used = True
                else:
                    execution.live_ssh_used = True
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                from rich.console import Console
                from .presentation import render_health
                render_health(Console(), results)
            if any(result["status"] != "success" for result in results):
                return 1
            return 2 if any(result["overall"] == "critical" for result in results) else 0
        elif args.command == "vpn":
            from rich.console import Console
            from .presentation import render_vpn_status
            execution.local_inventory_used = True
            result = application.network.vpn_status(args.device)
            if result["status"] in {"success", "partial"}:
                if args.mock:
                    execution.mock_used = True
                else:
                    execution.live_ssh_used = True
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_vpn_status(Console(), result)
            return 0 if result["status"] == "success" else 1
        elif args.command == "mac":
            from rich.console import Console
            from .presentation import (
                render_device_macs, render_interface_macs, render_mac_location,
                render_mac_scan,
            )
            execution.local_inventory_used = True
            service = application.mac

            def announce_collection(reason, target):
                scope = (
                    "all inventoried devices" if target.casefold() == "all"
                    else f"{target}"
                )
                if reason == "forced":
                    message = f"Collecting current MAC observations from {scope}..."
                else:
                    message = (
                        "MAC observations are missing or stale; collecting current "
                        f"data from {scope}..."
                    )
                print(message, file=sys.stderr, flush=True)

            if args.mac_action == "scan":
                announce_collection("forced", args.target)
                result = service.scan(args.target, args.workers)
                execution.mock_used = args.mock
                execution.live_ssh_used = not args.mock
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_mac_scan(Console(), result)
                return 0 if result["status"] == "success" else 1

            if args.mac_action == "port":
                result = service.interface_macs_current(
                    args.device, args.interface, args.max_age, args.workers,
                    args.refresh, announce_collection,
                )
                if result["refreshed"]:
                    execution.mock_used = args.mock
                    execution.live_ssh_used = not args.mock
                execution.mock_used = execution.mock_used or bool(result.get("mock"))
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_interface_macs(Console(), result)
                return 0 if result["complete"] else 1
            if args.mac_action == "table":
                result = service.device_macs_current(
                    args.device, args.max_age, args.workers, args.refresh,
                    announce_collection,
                )
                if result["refreshed"]:
                    execution.mock_used = args.mock
                    execution.live_ssh_used = not args.mock
                execution.mock_used = execution.mock_used or bool(result.get("mock"))
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_device_macs(Console(), result)
                return 0 if result["complete"] else 1
            query = (
                service.troubleshoot_current
                if args.mac_action == "troubleshoot" else service.locate_current
            )
            result = query(
                args.mac_address, args.max_age, args.workers, args.refresh,
                announce_collection,
            )
            if result["refreshed"]:
                execution.mock_used = args.mock
                execution.live_ssh_used = not args.mock
            execution.mock_used = execution.mock_used or bool(result.get("mock"))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_mac_location(
                    Console(), result,
                    troubleshooting=args.mac_action == "troubleshoot",
                )
            return 0 if result["found"] else 1
        elif args.command == "arp":
            from rich.console import Console
            from .presentation import render_device_arps
            execution.local_inventory_used = True

            def announce_arp_collection(reason, target):
                if reason == "forced":
                    message = f"Collecting current ARP observations from {target}..."
                else:
                    message = (
                        "ARP observations are missing or stale; collecting current "
                        f"data from {target}..."
                    )
                print(message, file=sys.stderr, flush=True)

            result = application.mac.device_arps_current(
                args.device, args.max_age, args.workers, args.refresh,
                announce_arp_collection,
            )
            if result["refreshed"]:
                execution.mock_used = args.mock
                execution.live_ssh_used = not args.mock
            execution.mock_used = execution.mock_used or bool(result.get("mock"))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_device_arps(Console(), result)
            return 0 if result["complete"] else 1
        elif args.command == "route":
            from rich.console import Console
            from .presentation import render_route_trace
            execution.local_inventory_used = True
            result = application.routing.trace(
                args.device, args.destination, args.workers
            )
            if result["status"] == "success":
                if args.mock:
                    execution.mock_used = True
                else:
                    execution.live_ssh_used = True
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_route_trace(Console(), result)
            return 0 if result["status"] == "success" else 1
        elif args.command == "endpoint":
            from rich.console import Console
            from .presentation import render_endpoint

            execution.local_inventory_used = True
            result = application.endpoints.locate(
                args.identifier, args.source_device, args.max_age,
                args.refresh, args.workers,
            )
            if args.refresh and result.get("collection_counts"):
                collected = (
                    result["collection_counts"].get("success", 0)
                    + result["collection_counts"].get("partial", 0)
                )
                if collected:
                    execution.mock_used = args.mock
                    execution.live_ssh_used = not args.mock
            else:
                execution.mock_used = bool(result.get("mock"))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_endpoint(Console(), result)
            return 0 if result["found"] else 1
        elif args.command == "path":
            from rich.console import Console
            from .presentation import render_mac_path

            execution.local_inventory_used = True
            result = application.mac_paths.trace(
                args.mac_address, args.source_device, args.max_age,
                args.refresh, args.workers,
            )
            if args.refresh and result.get("collection_counts"):
                collected = (
                    result["collection_counts"].get("success", 0)
                    + result["collection_counts"].get("partial", 0)
                )
                if collected:
                    execution.mock_used = args.mock
                    execution.live_ssh_used = not args.mock
            else:
                execution.mock_used = bool(result.get("mock"))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                render_mac_path(Console(), result)
            return 0 if result["complete"] else 1
        elif args.command == "topology":
            from rich.console import Console
            from .presentation import render_topology, render_topology_diagram

            execution.local_inventory_used = True
            use_mock = bool(getattr(args, "mock", False))
            service = application.topology
            if args.topology_action == "discover":
                result = service.discover(args.target, args.workers, args.max_age)
                collected = result["collection_counts"]["success"] + result["collection_counts"]["partial"]
                if collected:
                    execution.mock_used = use_mock
                    execution.live_ssh_used = not use_mock
            elif args.topology_action == "show":
                result = service.get(args.target, args.max_age)
            else:
                result = service.diagram(
                    args.target, args.location, args.max_age, args.output_format
                )
                if args.output:
                    target = Path(args.output).expanduser()
                    target.write_text(result["diagram"] + "\n", encoding="utf-8")
                    result["output_file"] = str(target)
            if getattr(args, "json", False):
                print(json.dumps(result, indent=2))
            elif args.topology_action == "diagram":
                if args.output:
                    print(f"Saved {args.output_format} topology diagram to {result['output_file']}.")
                elif args.output_format == "mermaid":
                    print(result["diagram"])
                else:
                    render_topology_diagram(Console(), result)
            else:
                render_topology(Console(), result)
            return 0 if result["complete"] else 1
        elif args.command == "snapshot":
            from rich.console import Console
            from .presentation import (
                render_baseline_comparison, render_baseline_metadata, render_baselines,
                render_configuration, render_fleet_baseline_comparison,
                render_fleet_baseline_creation, render_fleet_baseline_refresh,
                render_baseline_status,
            )
            execution.local_inventory_used = True
            use_mock = bool(getattr(args, "mock", False))
            baselines = application.baselines
            baseline_writes = application.baseline_writes
            if args.snapshot_action == "create":
                if args.device.casefold() == "all":
                    if args.replace:
                        raise InventoryError(
                            "Bulk baseline replacement is not allowed; replace devices individually."
                        )
                    authorization = baseline_writes.authorize_capture_all(args.source)
                    result = baseline_writes.capture_all(
                        args.source, args.workers, authorization=authorization
                    )
                    if result["counts"]["created"]:
                        execution.mock_used = use_mock
                        execution.live_ssh_used = not use_mock
                    if args.json:
                        print(json.dumps(result, indent=2))
                    else:
                        render_fleet_baseline_creation(Console(), result)
                    return result["exit_code"]
                authorization = baseline_writes.authorize_capture(
                    args.device, args.source, args.replace
                )
                result = baseline_writes.capture(
                    args.device, args.source, args.replace, authorization=authorization
                )
                if result["status"] == "success":
                    execution.mock_used = use_mock
                    execution.live_ssh_used = not use_mock
                if args.json:
                    print(json.dumps(result, indent=2))
                elif result["status"] == "success":
                    render_baseline_metadata(Console(), result["baseline"])
                    action = "Replaced" if result["replaced"] else "Created"
                    print(f"{action} sanitized configuration baseline for {args.device}.")
                else:
                    print(result["error"], file=sys.stderr)
                return 0 if result["status"] == "success" else 1
            if args.snapshot_action == "refresh":
                if not args.yes:
                    if args.json or not sys.stdin.isatty():
                        raise InventoryError(
                            "Bulk baseline refresh requires --yes in non-interactive or JSON mode."
                        )
                    answer = input(
                        "This will replace every existing configuration baseline. "
                        "Type REFRESH ALL to continue: "
                    )
                    if answer.strip() != "REFRESH ALL":
                        raise InventoryError("Bulk baseline refresh cancelled; no devices were contacted.")
                authorization = baseline_writes.authorize_refresh_all(args.source)
                result = baseline_writes.refresh_all(
                    args.source, args.workers, authorization=authorization
                )
                completed = result["counts"]["refreshed"] + result["counts"]["created"]
                if completed:
                    execution.mock_used = use_mock
                    execution.live_ssh_used = not use_mock
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_fleet_baseline_refresh(Console(), result)
                return result["exit_code"]
            if args.snapshot_action == "list":
                result = baselines.list()
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_baselines(Console(), result)
                return 0
            if args.snapshot_action == "status":
                result = baselines.status(args.max_age_days)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_baseline_status(Console(), result)
                return result["exit_code"]
            if args.snapshot_action == "show":
                result = baselines.get_full(args.device)
                if args.output:
                    target = Path(args.output).expanduser()
                    target.write_text(result["configuration"] + "\n", encoding="utf-8")
                    print(f"Saved sanitized configuration baseline to {target}.")
                elif args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_baseline_metadata(Console(), result)
                    render_configuration(Console(), result["configuration"])
                return 0
            if args.snapshot_action == "compare":
                if args.device.casefold() == "all":
                    if args.output:
                        raise InventoryError(
                            "--output is available only for a single-device comparison."
                        )
                    result = baselines.compare_all(args.workers)
                    checked = result["counts"]["unchanged"] + result["counts"]["changed"]
                    if checked:
                        execution.mock_used = use_mock
                        execution.live_ssh_used = not use_mock
                    if args.json:
                        print(json.dumps(result, indent=2))
                    else:
                        render_fleet_baseline_comparison(Console(), result)
                    return result["exit_code"]
                result = baselines.compare_full(args.device)
                if result["status"] == "success":
                    execution.mock_used = use_mock
                    execution.live_ssh_used = not use_mock
                if args.output and result["status"] == "success":
                    target = Path(args.output).expanduser()
                    target.write_text(result["diff"] + ("\n" if result["diff"] else ""), encoding="utf-8")
                    result["output_file"] = str(target)
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    render_baseline_comparison(Console(), result)
                    if args.output and result["status"] == "success":
                        print(f"Saved unified diff to {result['output_file']}.")
                return 0 if result["status"] == "success" else 1
            authorization = baseline_writes.authorize_remove(args.device)
            if not baseline_writes.remove(args.device, authorization=authorization):
                raise InventoryError("No configuration baseline exists for this device.")
            print(f"Removed configuration baseline for {args.device}.")
        elif args.command == "config":
            execution.local_inventory_used = True
            result = application.network.configuration(args.device, args.source)
            if result["status"] != "success":
                print(result["error"], file=sys.stderr)
                return 1
            if args.mock:
                execution.mock_used = True
            else:
                execution.live_ssh_used = True
            if args.output:
                target = Path(args.output).expanduser()
                target.write_text(result["output"] + "\n", encoding="utf-8")
                print(f"Saved sanitized {args.source} configuration to {target}.")
            else:
                from rich.console import Console
                from .presentation import render_configuration
                render_configuration(Console(), result["output"])
            print(
                f"Configuration revision {result['revision']}; "
                f"{result['redactions']} secret-bearing line(s) redacted.",
                file=sys.stderr,
            )
        else:
            execution.local_inventory_used = True
            network = application.network
            if args.operation == "get_configuration":
                result = network.get_configuration(args.device, args.source, args.cursor, args.revision)
            elif args.operation == "get_health":
                result = network.health(args.device)
            elif args.operation == "get_ospf_status":
                result = network.ospf_status(args.device)
            elif args.operation == "get_bgp_status":
                result = network.bgp_status(args.device)
            elif args.operation == "get_bgp_routes":
                result = network.bgp_routes(args.device)
            elif args.operation == "get_vpn_status":
                result = network.vpn_status(args.device)
            elif args.operation == "get_device_facts":
                result = network.discover_inventory(args.device)
            else:
                result = network.inspect(args.operation, args.device)
            if result["status"] == "success":
                if args.mock:
                    execution.mock_used = True
                else:
                    execution.live_ssh_used = True
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "success" else 1
    except (InventoryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        print("Cannot access the CSV, database or local process. Check paths and permissions.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        application.close()
        if execution is not None and not args.no_footer:
            from rich.console import Console
            from .presentation import render_execution
            sys.stdout.flush()
            render_execution(Console(stderr=True), execution)
    return 0
