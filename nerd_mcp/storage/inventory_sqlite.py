"""Local device inventory with atomic CSV and Excel imports."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ..domain.inventory import (
    DEVICE_FIELDS,
    Device,
    InventoryError,
    validate_inventory_text,
)
from .importers import load_inventory_import


class InventoryRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            db.execute("CREATE TABLE IF NOT EXISTS devices (name TEXT PRIMARY KEY, "
                       "host TEXT NOT NULL, port INTEGER NOT NULL, credential_profile TEXT NOT NULL)")
            existing = {row["name"] for row in db.execute("PRAGMA table_info(devices)")}
            defaults = {"vendor": "Cisco", "platform": "IOS/IOS-XE"}
            for field in DEVICE_FIELDS[4:]:
                if field not in existing:
                    default = defaults.get(field, "").replace("'", "''")
                    db.execute(f"ALTER TABLE devices ADD COLUMN {field} TEXT NOT NULL DEFAULT '{default}'")
            with db:
                yield db
        finally:
            db.close()

    def list(self) -> list[Device]:
        with self.connect() as db:
            columns = ", ".join(DEVICE_FIELDS)
            return [Device(**dict(row)) for row in db.execute(
                f"SELECT {columns} FROM devices ORDER BY name"
            )]

    def get(self, name: str) -> Device:
        with self.connect() as db:
            columns = ", ".join(DEVICE_FIELDS)
            row = db.execute(
                f"SELECT {columns} FROM devices WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
        if row is None:
            raise InventoryError("Unknown device; use devices list to select an inventoried name.")
        return Device(**dict(row))

    def remove(self, name: str) -> bool:
        with self.connect() as db:
            return db.execute(
                "DELETE FROM devices WHERE name = ? COLLATE NOCASE", (name,)
            ).rowcount > 0

    def search(self, *, city: str = "", state: str = "", location: str = "",
               device_type: str = "", hostname: str = "", country: str = "",
               serial_number: str = "", model: str = "", vendor: str = "",
               platform: str = "") -> list[Device]:
        """Search inventory with case-insensitive, parameterized filters."""
        filters = {
            "city": city,
            "state": state,
            "device_type": device_type,
            "country": country,
            "vendor": vendor,
            "platform": platform,
        }
        clauses, parameters = [], []
        for column, value in filters.items():
            if value.strip():
                clauses.append(f"LOWER({column}) = LOWER(?)")
                parameters.append(value.strip())
        if hostname.strip():
            clauses.append("(LOWER(name) LIKE LOWER(?) OR LOWER(device_hostname) LIKE LOWER(?))")
            term = f"%{hostname.strip()}%"
            parameters.extend((term, term))
        for column, value in (("serial_number", serial_number), ("model", model)):
            if value.strip():
                clauses.append(f"LOWER({column}) LIKE LOWER(?)")
                parameters.append(f"%{value.strip()}%")
        if location.strip():
            term = f"%{location.strip()}%"
            clauses.append("(" + " OR ".join(
                f"LOWER({column}) LIKE LOWER(?)"
                for column in ("location", "street_address", "city", "state", "zip_code", "country")
            ) + ")")
            parameters.extend([term] * 6)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connect() as db:
            columns = ", ".join(DEVICE_FIELDS)
            rows = db.execute(
                f"SELECT {columns} FROM devices{where} ORDER BY name", parameters
            ).fetchall()
        return [Device(**dict(row)) for row in rows]

    def update_facts(self, name: str, facts: dict[str, str]) -> Device:
        """Update device-observed facts while preserving operator-maintained location."""
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM devices WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
            if row is None:
                raise InventoryError("Unknown device; use devices list to select an inventoried name.")
            current = dict(row)
            for field in ("device_hostname", "serial_number", "model"):
                if facts.get(field):
                    current[field] = validate_inventory_text(field, facts[field])
            if facts.get("location") and current.get("location_source") != "csv":
                current["location"] = validate_inventory_text("location", facts["location"])
                current["location_source"] = "device"
            current["facts_updated_at"] = datetime.now(timezone.utc).isoformat()
            assignments = ", ".join(f"{field} = ?" for field in DEVICE_FIELDS[4:])
            db.execute(
                f"UPDATE devices SET {assignments} WHERE name = ? COLLATE NOCASE",
                [current[field] for field in DEVICE_FIELDS[4:]] + [current["name"]],
            )
        return self.get(name)

    def import_file(self, path: str | Path, update: bool = False) -> dict[str, int]:
        batch = load_inventory_import(path)
        errors: list[str] = []
        counts = {"added": 0, "updated": 0, "unchanged": 0}
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for record in batch.records:
                number = record.row_number
                values = asdict(record.device)
                existing_row = db.execute(
                    "SELECT * FROM devices WHERE name = ? COLLATE NOCASE", (values["name"],)
                ).fetchone()
                if existing_row is not None:
                    existing = dict(existing_row)
                    merged = dict(existing)
                    for field in ("host", "port", "credential_profile"):
                        merged[field] = values[field]
                    for field in batch.metadata_fields:
                        merged[field] = values[field]
                    if "location" in batch.metadata_fields:
                        merged["location_source"] = "csv" if values["location"] else ""
                    values = merged
                candidate = Device(**{field: values[field] for field in DEVICE_FIELDS})
                if existing_row is not None and dict(existing_row) == asdict(candidate):
                    counts["unchanged"] += 1
                elif existing_row is not None and not update:
                    errors.append(f"Row {number}: existing device differs; use --update to replace it")
                else:
                    counts["updated" if existing_row else "added"] += 1
                    placeholders = ", ".join("?" for _ in DEVICE_FIELDS)
                    columns = ", ".join(DEVICE_FIELDS)
                    db.execute(
                        f"INSERT OR REPLACE INTO devices ({columns}) VALUES ({placeholders})",
                        [getattr(candidate, field) for field in DEVICE_FIELDS],
                    )
            if errors:
                raise InventoryError("\n".join(errors))
        return counts

    def import_csv(self, path: str | Path, update: bool = False) -> dict[str, int]:
        """Compatibility wrapper for existing callers; also accepts .xlsx paths."""
        return self.import_file(path, update)


Inventory = InventoryRepository
