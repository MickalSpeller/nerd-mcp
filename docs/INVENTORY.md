# Inventory

Import CSV or XLSX with `python -m nerd_mcp devices import FILE`. Required columns are `name` and `host`; defaults are port 22 and profile `default`. Optional metadata includes hostname, location, address, country, serial, model, device type, vendor, and platform.

Imports are atomic, reject duplicate names, skip identical records, and require `--update` for conflicts. Use `devices list`, `devices search`, and `devices remove NAME`. Passwords never belong in inventory files. Device facts can supplement empty metadata after live inspection.
