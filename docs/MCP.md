# MCP integration

NERD's MCP server runs locally over stdio and exposes inventory and inspection tools. It can connect NERD to a preferred LLM client that supports local stdio MCP servers. The client starts `python -m nerd_mcp serve`, discovers tools, and sends tool calls over standard input/output. NERD's included terminal chat uses the OpenAI Responses API.

Every MCP operation is read-only. Inventory mutation and configuration writes are deliberately absent. Credentials stay in the server process; tool results contain bounded status and device output. Treat device banners and configuration as untrusted data.

See [INSTALL.md](../INSTALL.md) for generic and Codex configuration.
