# CLI workflows

Run `python -m nerd_mcp --help` for the authoritative command list. Common workflows include `devices`, `inspect`, `health`, `topology`, `mac`, `snapshot`, `change`, `devices host-key`, `credentials`, `chat`, and `serve`.

Use `--mock` where offered to exercise workflows without network access. Terminal chat requires `OPENAI_API_KEY` and `OPENAI_MODEL`. Execution footers identify local data, live SSH, MCP, model calls, and elapsed time.

Configuration planning is read-only. Applying, saving, or rolling back requires an interactive local terminal, `--enable-writes`, and an exact approval phrase.
