"""Durable, sanitized configuration change plans and audit events."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..domain.errors import InventoryError


class ChangeRepository:
    def __init__(self, inventory):
        self.inventory = inventory

    def _ensure(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS change_plans (
            change_id TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            error TEXT NOT NULL DEFAULT ''
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            details_json TEXT NOT NULL,
            FOREIGN KEY(change_id) REFERENCES change_plans(change_id) ON DELETE CASCADE
        )""")

    def put(self, plan: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(plan, separators=(",", ":"), sort_keys=True)
        with self.inventory.connect() as db:
            self._ensure(db)
            db.execute("""INSERT INTO change_plans
                (change_id, revision, state, created_at, updated_at, plan_json, error)
                VALUES (?, ?, ?, ?, ?, ?, '')""", (
                    plan["change_id"], plan["revision"], plan["state"],
                    plan["created_at"], now, payload,
                ))
            self._event(db, plan["change_id"], "prepared", {"revision": plan["revision"]})

    def get(self, change_id: str) -> dict:
        with self.inventory.connect() as db:
            self._ensure(db)
            row = db.execute(
                "SELECT * FROM change_plans WHERE change_id = ? COLLATE NOCASE", (change_id,)
            ).fetchone()
        if row is None:
            raise InventoryError("Unknown change ID; use change history to list plans.")
        plan = json.loads(row["plan_json"])
        plan["state"] = row["state"]
        plan["updated_at"] = row["updated_at"]
        plan["error"] = row["error"] or None
        return plan

    def transition(self, change_id: str, expected: tuple[str, ...], state: str,
                   event: str, details: dict | None = None, error: str = "") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self.inventory.connect() as db:
            self._ensure(db)
            row = db.execute(
                "SELECT state, plan_json FROM change_plans WHERE change_id = ? COLLATE NOCASE",
                (change_id,),
            ).fetchone()
            if row is None:
                raise InventoryError("Unknown change ID; use change history to list plans.")
            if row["state"] not in expected:
                raise InventoryError(
                    f"Change is {row['state']}; expected one of {', '.join(expected)}."
                )
            plan = json.loads(row["plan_json"]); plan["state"] = state
            db.execute("""UPDATE change_plans SET state=?, updated_at=?, plan_json=?, error=?
                          WHERE change_id=?""", (
                state, now, json.dumps(plan, separators=(",", ":"), sort_keys=True),
                error, change_id,
            ))
            self._event(db, change_id, event, details or {})
        return self.get(change_id)

    def event(self, change_id: str, event: str, details: dict | None = None) -> None:
        with self.inventory.connect() as db:
            self._ensure(db); self._event(db, change_id, event, details or {})

    @staticmethod
    def _event(db, change_id, event, details):
        db.execute(
            "INSERT INTO change_events(change_id,timestamp,event,details_json) VALUES(?,?,?,?)",
            (change_id, datetime.now(timezone.utc).isoformat(), event,
             json.dumps(details, separators=(",", ":"), sort_keys=True)),
        )

    def history(self) -> list[dict]:
        with self.inventory.connect() as db:
            self._ensure(db)
            return [dict(row) for row in db.execute(
                "SELECT change_id, revision, state, created_at, updated_at, error "
                "FROM change_plans ORDER BY created_at DESC"
            )]

    def events(self, change_id: str) -> list[dict]:
        self.get(change_id)
        with self.inventory.connect() as db:
            rows = db.execute(
                "SELECT timestamp,event,details_json FROM change_events "
                "WHERE change_id=? ORDER BY id", (change_id,)
            ).fetchall()
        return [{"timestamp": row["timestamp"], "event": row["event"],
                 "details": json.loads(row["details_json"])} for row in rows]

    def purge(self, before: str) -> int:
        try:
            cutoff = datetime.fromisoformat(before).astimezone(timezone.utc).isoformat()
        except ValueError as exc:
            raise InventoryError("--before must be an ISO date or timestamp.") from exc
        with self.inventory.connect() as db:
            self._ensure(db)
            return db.execute("DELETE FROM change_plans WHERE created_at < ?", (cutoff,)).rowcount
