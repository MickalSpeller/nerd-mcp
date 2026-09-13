# Installation

NERD requires Git, Python 3.11+, and direct SSH reachability for live devices. OpenAI is optional unless you use chat or natural-language planning.

## Install

Windows PowerShell:

```powershell
git clone https://github.com/MickalSpeller/nerd-mcp.git
cd nerd-mcp
py -3.11 -m venv .venv
Set-ExecutionPolicy -Scope Process RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[full]"
python -m nerd_mcp --version
```

Linux:

```bash
git clone https://github.com/MickalSpeller/nerd-mcp.git
cd nerd-mcp
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[full]'
python -m nerd_mcp --version
```

On macOS, install Python with Homebrew or python.org, then use the Linux commands.

| Extra | Contents |
|---|---|
| base | Inventory and direct inspection |
| `chat` | OpenAI terminal chat |
| `mcp` | MCP server |
| `full` | Chat and MCP |
| `test` | Test tools |

## Inventory and credentials

Copy `devices.example.csv`, replace its synthetic records, then import it:

```powershell
Copy-Item .\devices.example.csv .\devices.csv
python -m nerd_mcp devices import .\devices.csv
python -m nerd_mcp devices list
```

CSV and XLSX use the same headings. `name` and `host` are required; port defaults to 22 and credential profile to `default`. The whole file is validated atomically. Add `--update` for conflicting existing records.

On Windows:

```powershell
python -m nerd_mcp credentials set default
python -m nerd_mcp credentials status default
```

On Linux, macOS, or automation hosts:

```bash
export NERD_DEFAULT_USERNAME='network-user'
export NERD_DEFAULT_PASSWORD='value-from-your-secret-manager'  # pragma: allowlist secret (placeholder)
```

Legacy `CISCO_DEFAULT_USERNAME` and `CISCO_DEFAULT_PASSWORD` remain compatible for Cisco profiles. Never commit credentials.

## SSH trust and smoke tests

Verify the fingerprint through a trusted management channel before enrollment:

```powershell
python -m nerd_mcp devices host-key enroll edge-router-01
python -m nerd_mcp inspect edge-router-01 get_device_info
```

Mock tests need neither devices nor OpenAI:

```powershell
python -m nerd_mcp devices import .\devices.example.csv --update
python -m nerd_mcp inspect edge-router-01 get_device_info --mock
python -m nerd_mcp health edge-router-01 --mock
python -m nerd_mcp serve --mock
```

The server waits for an MCP client; press Ctrl+C when testing manually.

## OpenAI chat

```powershell
$env:OPENAI_API_KEY = Read-Host "OpenAI API key" -MaskInput
$env:OPENAI_MODEL = "YOUR_RESPONSES_API_MODEL"
python -m nerd_mcp chat --mock
```

Bash and zsh use `export OPENAI_API_KEY='...'` and `export OPENAI_MODEL='...'`. Chat sends relevant retrieved output to the OpenAI API.

## MCP and Codex

MCP uses stdio: the client launches NERD and exchanges JSON-RPC over standard input/output. A generic entry specifies the absolute Python executable and these arguments:

```json
{"command":"/absolute/path/.venv/bin/python","args":["-m","nerd_mcp","--db","/absolute/path/nerd.db","serve"]}
```

For Codex, edit `%USERPROFILE%\.codex\config.toml` on Windows or `~/.codex/config.toml` on Linux/macOS:

```toml
[mcp_servers.nerd]
command = "C:\\absolute\\path\\nerd-mcp\\.venv\\Scripts\\python.exe"
args = ["-m", "nerd_mcp", "--db", "C:\\absolute\\path\\nerd.db", "serve"]
cwd = "C:\\absolute\\path\\nerd-mcp"
```

Restart Codex. NERD registers no MCP write tools.

## Runtime files, upgrades, and removal

SQLite stores inventory, baselines, observations, and audits at the configured database path. Known hosts live in NERD's application-data directory; Windows secrets live in Credential Manager. Check command help for path overrides.

Upgrade with `git pull --ff-only`, reinstall `.[full]`, and check `python -m nerd_mcp --version`. Uninstall with `python -m pip uninstall nerd-mcp-assistant`. For clean removal, export needed data, delete the clone, then explicitly remove the database, known-hosts file, and Credential Manager entries.

See [troubleshooting](docs/TROUBLESHOOTING.md).
