# Architecture

The terminal CLI and stdio MCP server share application services but enforce different capabilities.

```mermaid
flowchart LR
  CLI[Local CLI] --> APP[Application services]
  CHAT[OpenAI chat] --> APP
  MCP[Read-only MCP] --> APP
  APP --> DOMAIN[Typed domain models and policy]
  APP --> ADAPTER[Vendor adapters]
  ADAPTER --> SSH[Bounded Netmiko transport]
  APP --> DB[(Local SQLite)]
```

Domain models define devices, evidence, diagnoses, baselines, and typed changes. Application services coordinate use cases. Storage adapters persist local state. Vendor adapters own commands and parsing. Transport owns verified SSH, timeouts, pooling, cleanup, and redaction. Compatibility facades preserve earlier public APIs.

The LLM interprets normalized evidence and can propose typed operations. It cannot emit executable raw CLI, authorize a change, call the write transport, or save configuration.
