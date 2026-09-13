"""NERD settings with compatibility for existing installations."""

import os
from pathlib import Path


def env(name, default=None):
    value = os.getenv(name)
    if value is None and name.startswith("NERD_"):
        value = os.getenv("CISCO_" + name[5:])
    return value if value is not None else default


def default_database():
    root = Path(os.getenv("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    modern = root / "nerd-mcp" / "devices.db"
    legacy = root / "cisco-mcp" / "devices.db"
    return env("NERD_MCP_DB", str(modern if modern.exists() or not legacy.exists() else legacy))
