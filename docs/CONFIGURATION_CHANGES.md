# Controlled configuration changes

Cisco IOS/IOS-XE writes are experimental. Other adapters stay read-only until their rollback, verification, and live-version gates pass.

The workflow is: typed request, live preflight, deterministic adapter rendering, colored diff, exact apply approval, verification, affected live configuration, and separate save approval. Plans and sanitized audit events are stored in SQLite. MCP and model tool calls cannot write.

```powershell
python -m nerd_mcp change plan --device edge-router-01 --request "Set Loopback0 description to Example peer"
python -m nerd_mcp change show CHG-XXXXXXXXXXXX
python -m nerd_mcp change apply CHG-XXXXXXXXXXXX --enable-writes
python -m nerd_mcp change save CHG-XXXXXXXXXXXX --enable-writes
```

Review the generated plan and rollback details. Exact `APPLY`, `SAVE`, and `ROLLBACK` phrases are single-use authorizations bound to plan state. A stale preflight is rejected. Changes remain unsaved until separately approved. Baselines are never updated automatically.
