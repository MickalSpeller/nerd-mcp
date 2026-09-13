"""Durable sanitized diagnosis workflow records."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..domain.errors import InventoryError


class DiagnosisRepository:
    def __init__(self, inventory):
        self.inventory = inventory

    @staticmethod
    def _ensure(db):
        db.execute("""CREATE TABLE IF NOT EXISTS diagnosis_workflows (
            diagnosis_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            change_id TEXT,
            decision TEXT NOT NULL DEFAULT '',
            report_json TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS diagnosis_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            diagnosis_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            details_json TEXT NOT NULL,
            FOREIGN KEY(diagnosis_id) REFERENCES diagnosis_workflows(diagnosis_id)
                ON DELETE CASCADE
        )""")

    def put(self, report: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.inventory.connect() as db:
            self._ensure(db)
            db.execute("""INSERT INTO diagnosis_workflows
                (diagnosis_id,state,created_at,updated_at,change_id,decision,report_json)
                VALUES(?,?,?,?,?,?,?)""", (
                report["diagnosis_id"], report["state"], report["created_at"], now,
                report.get("change_id"), report.get("decision") or "",
                json.dumps(report, separators=(",", ":"), sort_keys=True),
            ))
            self._event(db, report["diagnosis_id"], report["state"], {})

    def get(self, diagnosis_id: str) -> dict:
        with self.inventory.connect() as db:
            self._ensure(db)
            row = db.execute(
                "SELECT * FROM diagnosis_workflows WHERE diagnosis_id=? COLLATE NOCASE",
                (diagnosis_id,),
            ).fetchone()
        if row is None:
            raise InventoryError("Unknown diagnosis ID.")
        result = json.loads(row["report_json"])
        result.update({
            "state": row["state"], "updated_at": row["updated_at"],
            "change_id": row["change_id"], "decision": row["decision"] or None,
        })
        return result

    def transition(self, diagnosis_id: str, state: str, event: str,
                   *, change_id: str | None = None, decision: str | None = None,
                   details: dict | None = None) -> dict:
        current = self.get(diagnosis_id)
        current.update({"state": state})
        if change_id is not None:
            current["change_id"] = change_id
        if decision is not None:
            current["decision"] = decision
        now = datetime.now(timezone.utc).isoformat()
        with self.inventory.connect() as db:
            self._ensure(db)
            db.execute("""UPDATE diagnosis_workflows SET state=?,updated_at=?,change_id=?,
                decision=?,report_json=? WHERE diagnosis_id=?""", (
                state, now, current.get("change_id"), current.get("decision") or "",
                json.dumps(current, separators=(",", ":"), sort_keys=True), diagnosis_id,
            ))
            self._event(db, diagnosis_id, event, details or {})
        return self.get(diagnosis_id)

    @staticmethod
    def _event(db, diagnosis_id, event, details):
        db.execute(
            "INSERT INTO diagnosis_events(diagnosis_id,timestamp,event,details_json) VALUES(?,?,?,?)",
            (diagnosis_id, datetime.now(timezone.utc).isoformat(), event,
             json.dumps(details, separators=(",", ":"), sort_keys=True)),
        )
