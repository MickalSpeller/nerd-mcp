# NERD CLI command examples

This guide shows two ways to use NERD:

- **PowerShell commands** run directly at the `PS>` prompt.
- **Natural-language prompts** are entered after starting chat and seeing `Ask N.E.R.D. ›`.

The examples use fictional devices and reserved documentation addresses. Replace device names with names from your own inventory.

## Start in PowerShell

From the cloned `nerd-mcp` directory:

```powershell
.\.venv\Scripts\Activate.ps1
python -m nerd_mcp --version
python -m nerd_mcp --help
```

For help with a particular command:

```powershell
python -m nerd_mcp devices --help
python -m nerd_mcp inspect --help
python -m nerd_mcp snapshot --help
python -m nerd_mcp change --help
```

## Inventory and credentials

```powershell
# Import the example inventory or your own CSV/XLSX file.
python -m nerd_mcp devices import .\devices.example.csv
python -m nerd_mcp devices import .\devices.csv --update

# List, show, search, and remove inventory records.
python -m nerd_mcp devices list
python -m nerd_mcp devices show edge-router-01
python -m nerd_mcp devices search --city "Example City"
python -m nerd_mcp devices search --state TX
python -m nerd_mcp devices search --device-type firewall
python -m nerd_mcp devices remove edge-router-01

# Manage a credential profile on Windows.
python -m nerd_mcp credentials set default
python -m nerd_mcp credentials status default
python -m nerd_mcp credentials remove default

# Collect missing facts such as hostname, model, and serial number.
python -m nerd_mcp devices refresh edge-router-01
python -m nerd_mcp devices refresh all
```

Passwords are prompted for or read from the supported credential source. Never place passwords in inventory files or commands.

## SSH host keys and connectivity

After independently verifying a new device's SSH fingerprint:

```powershell
python -m nerd_mcp devices host-key enroll edge-router-01
python -m nerd_mcp inspect edge-router-01 get_device_info
```

Use `--mock` to test without connecting to a device:

```powershell
python -m nerd_mcp inspect edge-router-01 get_device_info --mock
python -m nerd_mcp health edge-router-01 --mock
```

## Read-only inspection

```powershell
python -m nerd_mcp inspect edge-router-01 get_device_info
python -m nerd_mcp inspect edge-router-01 get_device_facts
python -m nerd_mcp inspect edge-router-01 get_interfaces
python -m nerd_mcp inspect access-switch-01 get_vlans
python -m nerd_mcp inspect edge-router-01 get_routes
python -m nerd_mcp inspect edge-router-01 get_neighbors
python -m nerd_mcp inspect edge-router-01 get_ospf_status
python -m nerd_mcp inspect edge-router-01 get_bgp_status
python -m nerd_mcp inspect edge-router-01 get_bgp_routes
python -m nerd_mcp inspect firewall-01 get_vpn_status
python -m nerd_mcp inspect edge-router-01 get_configuration --source running
python -m nerd_mcp config edge-router-01 --source running
python -m nerd_mcp config edge-router-01 --output .\edge-router-01-sanitized.txt
```

Add `--json` to commands that offer it when machine-readable output is needed. Run the command's `--help` to see its available options.

## Health, topology, routes, and endpoints

```powershell
# Health checks.
python -m nerd_mcp health edge-router-01
python -m nerd_mcp health all

# Discover and display topology.
python -m nerd_mcp topology discover all
python -m nerd_mcp topology show all
python -m nerd_mcp topology diagram all
python -m nerd_mcp topology diagram all --format mermaid --output .\topology.mmd

# Trace an exact IPv4 route.
python -m nerd_mcp route trace edge-router-01 198.51.100.25

# Refresh and query MAC/ARP observations.
python -m nerd_mcp mac scan all
python -m nerd_mcp mac table access-switch-01
python -m nerd_mcp mac port access-switch-01 Ethernet1/1
python -m nerd_mcp mac locate 00:11:22:33:44:55
python -m nerd_mcp mac troubleshoot 00:11:22:33:44:55 --refresh
python -m nerd_mcp arp table edge-router-01
python -m nerd_mcp endpoint locate 198.51.100.25 --refresh
python -m nerd_mcp path mac 00:11:22:33:44:55 --from edge-router-01

# FortiOS VPN status.
python -m nerd_mcp vpn status firewall-01
```

## Configuration baselines

NERD keeps one sanitized baseline per device. Replacing a baseline overwrites that device's previous baseline.

```powershell
python -m nerd_mcp snapshot create edge-router-01
python -m nerd_mcp snapshot create edge-router-01 --replace
python -m nerd_mcp snapshot list
python -m nerd_mcp snapshot status --max-age-days 30
python -m nerd_mcp snapshot show edge-router-01
python -m nerd_mcp snapshot compare edge-router-01
python -m nerd_mcp snapshot compare all
python -m nerd_mcp snapshot refresh all
python -m nerd_mcp snapshot remove edge-router-01
```

Bulk refresh asks for confirmation. For a non-interactive run, use `snapshot refresh all --yes` only after reviewing what it replaces.

## Natural-language chat

Set `OPENAI_API_KEY` and `OPENAI_MODEL` as described in [INSTALL.md](../INSTALL.md), then start chat:

```powershell
python -m nerd_mcp chat
```

At the `Ask N.E.R.D. ›` prompt, examples include:

```text
/version
Tell me about edge-router-01.
Show all interfaces on access-switch-01.
Is OSPF running on edge-router-01?
Show the BGP neighbors and session uptime on edge-router-01.
Are there any BGP problems between edge-router-01 and branch-router-01?
What devices are located at Example HQ?
Show all devices located in TX.
What MAC addresses are learned on access-switch-01 Ethernet1/1?
Locate 00:11:22:33:44:55.
What devices are connected to access-switch-01?
Compare edge-router-01 with its configuration baseline.
Update the edge-router-01 baseline.
```

`/version` displays the installed NERD version and creator without making an OpenAI API call.

Chat uses OpenAI for natural-language interpretation. Direct commands such as `inspect`, `health`, and `devices list` do not require OpenAI.

## Controlled configuration changes

Planning is read-only. Applying, saving, and rolling back are experimental, terminal-only actions. They require `--enable-writes` and an exact approval phrase. MCP tools cannot change devices.

Start an interactive chat that can offer the controlled write workflow:

```powershell
python -m nerd_mcp chat --enable-writes
```

Example chat requests:

```text
On edge-router-01, change the Loopback0 description to Example BGP peer.
On edge-router-01, change Loopback0 to 192.0.2.25/32.
Diagnose the BGP problem between edge-router-01 and branch-router-01 and recommend a correction.
Show the proposed changes.
```

NERD displays live evidence, a configuration diff, and an Apply/Details/Ignore decision. Selecting Apply still requires typing the exact phrase displayed by NERD, such as `APPLY CHG-XXXXXXXXXXXX`. Saving requires a separate `SAVE CHG-XXXXXXXXXXXX` approval.

The explicit PowerShell workflow is:

```powershell
python -m nerd_mcp change plan --device edge-router-01 --request "Set Loopback0 description to Example BGP peer"
python -m nerd_mcp change show CHG-XXXXXXXXXXXX
python -m nerd_mcp change status CHG-XXXXXXXXXXXX
python -m nerd_mcp change apply CHG-XXXXXXXXXXXX --enable-writes
python -m nerd_mcp change save CHG-XXXXXXXXXXXX --enable-writes
python -m nerd_mcp change history
```

Replace `CHG-XXXXXXXXXXXX` with the change ID returned by the plan command. Review [controlled configuration changes](CONFIGURATION_CHANGES.md) before enabling writes. Platform support is listed in the main [README](../README.md).

## Standalone MCP server

Start the read-only stdio MCP server with:

```powershell
python -m nerd_mcp serve
```

For a connection-free smoke test:

```powershell
python -m nerd_mcp serve --mock
```

A stdio MCP server normally waits silently for an MCP client and does not display an interactive prompt. See [MCP integration](MCP.md) for client configuration.
