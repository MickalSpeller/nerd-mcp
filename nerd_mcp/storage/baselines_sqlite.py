"""SQLite persistence for sanitized configuration baselines and comparison status."""

from contextlib import contextmanager

from ..domain.ports import InventoryPort


class BaselineRepository:
    def __init__(self, inventory: InventoryPort):
        self.inventory = inventory

    @contextmanager
    def connect(self):
        with self.inventory.connect() as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("""CREATE TABLE IF NOT EXISTS configuration_baselines (
                device_name TEXT PRIMARY KEY REFERENCES devices(name) ON DELETE CASCADE,
                source TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                revision TEXT NOT NULL,
                configuration TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                redactions INTEGER NOT NULL DEFAULT 0,
                ignored_volatile_lines INTEGER NOT NULL DEFAULT 0,
                mock INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS configuration_comparison_status (
                device_name TEXT PRIMARY KEY REFERENCES devices(name) ON DELETE CASCADE,
                status TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL,
                baseline_revision TEXT NOT NULL DEFAULT '',
                current_revision TEXT NOT NULL DEFAULT '',
                added_lines INTEGER NOT NULL DEFAULT 0,
                removed_lines INTEGER NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '',
                mock INTEGER NOT NULL DEFAULT 0
            )""")
            yield db

    def get(self, device: str):
        with self.connect() as db:
            return db.execute(
                "SELECT * FROM configuration_baselines WHERE device_name = ?", (device,)
            ).fetchone()

    def list(self):
        with self.connect() as db:
            return list(db.execute("SELECT * FROM configuration_baselines ORDER BY device_name"))

    def captured_at(self, device: str):
        with self.connect() as db:
            return db.execute(
                "SELECT captured_at FROM configuration_baselines WHERE device_name = ?", (device,)
            ).fetchone()

    def save(self, values: tuple, replace: bool) -> None:
        with self.connect() as db:
            if replace:
                db.execute("""INSERT INTO configuration_baselines
                    (device_name, source, captured_at, revision, configuration, total_lines,
                     redactions, ignored_volatile_lines, mock)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(device_name) DO UPDATE SET source=excluded.source,
                    captured_at=excluded.captured_at, revision=excluded.revision,
                    configuration=excluded.configuration, total_lines=excluded.total_lines,
                    redactions=excluded.redactions,
                    ignored_volatile_lines=excluded.ignored_volatile_lines, mock=excluded.mock""", values)
            else:
                db.execute("""INSERT INTO configuration_baselines
                    (device_name, source, captured_at, revision, configuration, total_lines,
                     redactions, ignored_volatile_lines, mock)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", values)
            db.execute(
                "DELETE FROM configuration_comparison_status WHERE device_name = ?", (values[0],)
            )

    def remove(self, device: str) -> bool:
        with self.connect() as db:
            removed = db.execute(
                "DELETE FROM configuration_baselines WHERE device_name = ?", (device,)
            ).rowcount > 0
            db.execute(
                "DELETE FROM configuration_comparison_status WHERE device_name = ?", (device,)
            )
            return removed

    def record_comparison(self, summary: dict[str, object], checked_at: str) -> None:
        with self.connect() as db:
            db.execute("""INSERT INTO configuration_comparison_status
                (device_name, status, source, checked_at, baseline_revision,
                 current_revision, added_lines, removed_lines, error, mock)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET status=excluded.status,
                source=excluded.source, checked_at=excluded.checked_at,
                baseline_revision=excluded.baseline_revision,
                current_revision=excluded.current_revision,
                added_lines=excluded.added_lines, removed_lines=excluded.removed_lines,
                error=excluded.error, mock=excluded.mock""", (
                    summary["device"], summary["status"], summary["source"], checked_at,
                    summary["baseline_revision"], summary["current_revision"],
                    summary["added_lines"], summary["removed_lines"], summary["error"],
                    int(summary["mock"]),
                ))

    def status_rows(self):
        with self.connect() as db:
            return list(db.execute("""SELECT d.name AS device_name,
                b.source AS baseline_source, b.captured_at AS baseline_captured_at,
                b.revision AS baseline_revision, b.mock AS baseline_mock,
                c.status AS comparison_status, c.checked_at, c.current_revision,
                c.added_lines, c.removed_lines, c.error, c.mock AS comparison_mock
                FROM devices d
                LEFT JOIN configuration_baselines b ON b.device_name = d.name
                LEFT JOIN configuration_comparison_status c ON c.device_name = d.name
                ORDER BY d.name"""))
