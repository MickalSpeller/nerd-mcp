"""Single retained sanitized configuration baseline per inventory device."""

from __future__ import annotations

import difflib
import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ..domain.errors import InventoryError, MissingBaselineError
from ..domain.ports import BaselineRepositoryPort, InventoryPort, NetworkPort

BASELINE_PAGE_CHARS = 12_000
DIFF_PAGE_CHARS = 12_000
MAX_BASELINE_CHARS = 5_000_000
DEFAULT_BASELINE_MAX_AGE_DAYS = 30
LOG = logging.getLogger("nerd_mcp.operations")

VOLATILE_CONFIGURATION_LINES = (
    re.compile(r"^Building configuration\.\.\.$", re.IGNORECASE),
    re.compile(r"^Current configuration\s*:\s*\d+ bytes$", re.IGNORECASE),
    re.compile(r"^!?\s*Last configuration change at\b.*$", re.IGNORECASE),
    re.compile(r"^!?\s*NVRAM config last updated at\b.*$", re.IGNORECASE),
)


def normalize_configuration(value: str) -> tuple[str, int]:
    """Normalize line endings and omit volatile IOS display metadata from comparisons."""
    kept = []
    ignored = 0
    for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.rstrip()
        if any(pattern.match(line.strip()) for pattern in VOLATILE_CONFIGURATION_LINES):
            ignored += 1
            continue
        kept.append(line)
    while kept and not kept[0]:
        kept.pop(0)
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept), ignored


def _revision(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class ConfigurationBaselineWorkflow:
    """Baseline workflow with collection and storage supplied by its caller."""

    def __init__(self, inventory: InventoryPort, mock: bool,
                 network: NetworkPort,
                 repository: BaselineRepositoryPort, error_mapper,
                 baseline_page_chars: int = BASELINE_PAGE_CHARS,
                 diff_page_chars: int = DIFF_PAGE_CHARS,
                 max_baseline_chars: int = MAX_BASELINE_CHARS):
        self.inventory = inventory
        self.mock = mock
        self.network = network
        self.repository = repository
        self.error_mapper = error_mapper
        self.baseline_page_chars = baseline_page_chars
        self.diff_page_chars = diff_page_chars
        self.max_baseline_chars = max_baseline_chars

    def connect(self):
        """Compatibility access to the baseline repository transaction."""
        return self.repository.connect()

    @staticmethod
    def _metadata(row) -> dict[str, object]:
        return {
            "device": row["device_name"],
            "source": row["source"],
            "captured_at": row["captured_at"],
            "revision": row["revision"],
            "total_chars": len(row["configuration"]),
            "total_lines": row["total_lines"],
            "redactions": row["redactions"],
            "ignored_volatile_lines": row["ignored_volatile_lines"],
            "mock": bool(row["mock"]),
        }

    def _row(self, device: str):
        self.inventory.get(device)
        row = self.repository.get(device)
        if row is None:
            raise MissingBaselineError(
                "No configuration baseline exists for this device; create one with the snapshot CLI."
            )
        return row

    def list(self) -> dict[str, object]:
        rows = self.repository.list()
        return {"status": "success", "count": len(rows),
                "baselines": [self._metadata(row) for row in rows]}

    def capture(self, device: str, source: str = "running", replace: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "status": "error", "device": device, "source": source, "replaced": False,
            "baseline": None, "error": None, "mock": self.mock,
        }
        try:
            if source not in {"running", "startup"}:
                raise InventoryError("Unsupported configuration source; use running or startup.")
            if not isinstance(replace, bool):
                raise InventoryError("Replace must be true or false.")
            self.inventory.get(device)
            existing = self.repository.captured_at(device)
            if existing and not replace:
                raise InventoryError(
                    "A baseline already exists. Use --replace to approve overwriting it."
                )
            current = self.network.configuration(device, source)
            if current["status"] != "success":
                raise InventoryError(current["error"] or "Configuration collection failed.")
            configuration = current["output"]
            if len(configuration) > self.max_baseline_chars:
                raise InventoryError(
                    f"Sanitized configuration exceeds the {self.max_baseline_chars:,}-character baseline limit."
                )
            normalized, ignored = normalize_configuration(configuration)
            captured_at = current["timestamp"]
            revision = _revision(normalized)
            values = (
                device, source, captured_at, revision, configuration,
                len(configuration.splitlines()), current["redactions"], ignored, int(self.mock),
            )
            self.repository.save(values, replace)
            row = self._row(device)
            result.update({
                "status": "success", "replaced": bool(existing), "baseline": self._metadata(row),
            })
        except Exception as exc:
            result["error"] = self.error_mapper(exc)
        LOG.info("operation=capture_configuration_baseline device=%s status=%s mock=%s",
                 device, result["status"], self.mock)
        return result

    def capture_all(self, source: str = "running", workers: int = 4) -> dict[str, object]:
        """Create only missing baselines across inventory and preserve every existing baseline."""
        if source not in {"running", "startup"}:
            raise InventoryError("Unsupported configuration source; use running or startup.")
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
            raise InventoryError("Workers must be an integer from 1 to 16.")
        devices = self.inventory.list()
        if not devices:
            raise InventoryError("No devices are inventoried.")
        existing = {item["device"]: item for item in self.list()["baselines"]}
        results: dict[str, dict[str, object]] = {
            name: {
                "device": name, "status": "existing", "source": baseline["source"],
                "captured_at": baseline["captured_at"], "revision": baseline["revision"],
                "error": "", "mock": baseline["mock"],
            }
            for name, baseline in existing.items()
        }
        targets = [device for device in devices if device.name not in existing]
        if targets:
            with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
                futures = {
                    pool.submit(self.capture, device.name, source, False): device.name
                    for device in targets
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        capture = future.result()
                    except Exception as exc:
                        capture = {
                            "status": "error", "device": name, "error": self.error_mapper(exc),
                            "mock": self.mock,
                        }
                    baseline = capture.get("baseline") or {}
                    results[name] = {
                        "device": name,
                        "status": "created" if capture.get("status") == "success" else "failed",
                        "source": baseline.get("source", source),
                        "captured_at": baseline.get("captured_at", ""),
                        "revision": baseline.get("revision", ""),
                        "error": capture.get("error") or "",
                        "mock": bool(capture.get("mock", self.mock)),
                    }
        ordered = [results[device.name] for device in devices]
        counts = {
            state: sum(result["status"] == state for result in ordered)
            for state in ("created", "existing", "failed")
        }
        return {
            "status": "success" if not counts["failed"] else "partial",
            "complete": not counts["failed"],
            "counts": {"total": len(ordered), **counts},
            "exit_code": 0 if not counts["failed"] else 1,
            "results": ordered,
            "source": source,
            "mock": self.mock,
        }

    def refresh_all(self, source: str | None = None, workers: int = 4) -> dict[str, object]:
        """Replace existing baselines and create missing ones across the inventory."""
        if source is not None and source not in {"running", "startup"}:
            raise InventoryError("Unsupported configuration source; use running or startup.")
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
            raise InventoryError("Workers must be an integer from 1 to 16.")
        devices = self.inventory.list()
        if not devices:
            raise InventoryError("No devices are inventoried.")
        existing = {item["device"]: item for item in self.list()["baselines"]}
        results: dict[str, dict[str, object]] = {}
        with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
            futures = {}
            for device in devices:
                previous = existing.get(device.name)
                selected_source = source or (previous["source"] if previous else "running")
                futures[pool.submit(
                    self.capture, device.name, selected_source, previous is not None
                )] = (device.name, selected_source, previous)
            for future in as_completed(futures):
                name, selected_source, previous = futures[future]
                try:
                    capture = future.result()
                except Exception as exc:
                    capture = {
                        "status": "error", "device": name, "error": self.error_mapper(exc),
                        "mock": self.mock,
                    }
                baseline = capture.get("baseline") or {}
                succeeded = capture.get("status") == "success"
                results[name] = {
                    "device": name,
                    "status": ("refreshed" if previous else "created") if succeeded else "failed",
                    "source": baseline.get("source", selected_source),
                    "previous_captured_at": previous["captured_at"] if previous else "",
                    "captured_at": baseline.get("captured_at", ""),
                    "revision": baseline.get("revision", ""),
                    "error": capture.get("error") or "",
                    "mock": bool(capture.get("mock", self.mock)),
                }
        ordered = [results[device.name] for device in devices]
        counts = {
            state: sum(result["status"] == state for result in ordered)
            for state in ("refreshed", "created", "failed")
        }
        return {
            "status": "success" if not counts["failed"] else "partial",
            "complete": not counts["failed"],
            "counts": {"total": len(ordered), **counts},
            "exit_code": 0 if not counts["failed"] else 1,
            "results": ordered,
            "source": source or "preserve",
            "mock": self.mock,
        }

    def remove(self, device: str) -> bool:
        self.inventory.get(device)
        return self.repository.remove(device)

    def get_full(self, device: str) -> dict[str, object]:
        row = self._row(device)
        return {"status": "success", **self._metadata(row), "configuration": row["configuration"]}

    def get_page(self, device: str, cursor: int, revision: str) -> dict[str, object]:
        try:
            baseline = self.get_full(device)
            configuration = baseline.pop("configuration")
            if not isinstance(cursor, int) or isinstance(cursor, bool) or not 0 <= cursor <= len(configuration):
                raise InventoryError("Invalid baseline cursor.")
            if revision and revision != baseline["revision"]:
                raise InventoryError("The baseline changed between pages; restart with cursor 0.")
            end = min(cursor + self.baseline_page_chars, len(configuration))
            return {
                **baseline,
                "cursor": cursor,
                "next_cursor": None if end == len(configuration) else end,
                "complete": end == len(configuration),
                "output": configuration[cursor:end],
                "error": None,
            }
        except Exception as exc:
            return {
                "status": "error", "device": device, "cursor": cursor, "next_cursor": None,
                "complete": False, "output": "", "error": self.error_mapper(exc),
            }

    def _build_comparison(self, device: str) -> dict[str, object]:
        baseline = self.get_full(device)
        if baseline["mock"] != self.mock:
            raise InventoryError(
                "The baseline capture mode does not match this comparison; use the same mock or live mode."
            )
        current = self.network.configuration(device, baseline["source"])
        if current["status"] != "success":
            raise InventoryError(current["error"] or "Current configuration collection failed.")
        if len(current["output"]) > self.max_baseline_chars:
            raise InventoryError(
                f"Sanitized current configuration exceeds the {self.max_baseline_chars:,}-character limit."
            )
        baseline_normalized, baseline_ignored = normalize_configuration(baseline["configuration"])
        current_normalized, current_ignored = normalize_configuration(current["output"])
        current_revision = _revision(current_normalized)
        diff_lines = list(difflib.unified_diff(
            baseline_normalized.splitlines(), current_normalized.splitlines(),
            fromfile=f"{device} baseline {baseline['captured_at']}",
            tofile=f"{device} current", lineterm="",
        ))
        diff = "\n".join(diff_lines)
        added = sum(line.startswith("+") and not line.startswith("+++") for line in diff_lines)
        removed = sum(line.startswith("-") and not line.startswith("---") for line in diff_lines)
        comparison_revision = _revision(
            f"{baseline['revision']}:{current_revision}:{diff}"
        )
        return {
            "status": "success",
            "device": device,
            "source": baseline["source"],
            "baseline_captured_at": baseline["captured_at"],
            "compared_at": current["timestamp"],
            "baseline_revision": baseline["revision"],
            "current_revision": current_revision,
            "comparison_revision": comparison_revision,
            "changed": baseline["revision"] != current_revision,
            "added_lines": added,
            "removed_lines": removed,
            "baseline_ignored_volatile_lines": baseline_ignored,
            "current_ignored_volatile_lines": current_ignored,
            "current_redactions": current["redactions"],
            "baseline_mock": baseline["mock"],
            "mock": self.mock,
            "diff": diff,
        }

    def _baseline_context(self, device: str) -> dict[str, object]:
        try:
            baseline = self.get_full(device)
        except Exception:
            return {}
        return {
            "source": baseline["source"],
            "baseline_captured_at": baseline["captured_at"],
            "baseline_revision": baseline["revision"],
            "baseline_mock": baseline["mock"],
        }

    @staticmethod
    def _comparison_state(result: dict[str, object]) -> str:
        if result.get("status") == "success":
            return "changed" if result.get("changed") else "unchanged"
        if result.get("approval_required"):
            return "missing"
        return "failed"

    @classmethod
    def _comparison_summary(cls, result: dict[str, object]) -> dict[str, object]:
        return {
            "device": result.get("device", ""),
            "status": cls._comparison_state(result),
            "source": result.get("source") or (
                result.get("snapshot_proposal") or {}
            ).get("source", ""),
            "baseline_captured_at": result.get("baseline_captured_at", ""),
            "compared_at": result.get("compared_at", ""),
            "baseline_revision": result.get("baseline_revision", ""),
            "current_revision": result.get("current_revision", ""),
            "added_lines": result.get("added_lines", 0),
            "removed_lines": result.get("removed_lines", 0),
            "error": result.get("error") or "",
            "mock": bool(result.get("mock")),
        }

    def _record_comparison(self, result: dict[str, object]) -> None:
        summary = self._comparison_summary(result)
        checked_at = summary["compared_at"] or datetime.now(timezone.utc).isoformat()
        try:
            self.repository.record_comparison(summary, checked_at)
        except Exception:
            LOG.warning(
                "operation=record_configuration_comparison device=%s status=error",
                summary["device"],
            )

    def status(self, max_age_days: int = DEFAULT_BASELINE_MAX_AGE_DAYS,
               now: datetime | None = None) -> dict[str, object]:
        """Return current baseline and latest comparison metadata without configuration text."""
        if (not isinstance(max_age_days, int) or isinstance(max_age_days, bool)
                or not 0 <= max_age_days <= 36_500):
            raise InventoryError("Maximum baseline age must be an integer from 0 to 36500 days.")
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        current_time = current_time.astimezone(timezone.utc)
        rows = self.repository.status_rows()
        devices = []
        for row in rows:
            has_baseline = row["baseline_revision"] is not None
            age_days = None
            stale = False
            if has_baseline:
                captured = datetime.fromisoformat(
                    row["baseline_captured_at"].replace("Z", "+00:00")
                )
                if captured.tzinfo is None:
                    captured = captured.replace(tzinfo=timezone.utc)
                age_seconds = max(0.0, (current_time - captured.astimezone(timezone.utc)).total_seconds())
                age_days = int(age_seconds // 86_400)
                stale = age_seconds > max_age_days * 86_400
            devices.append({
                "device": row["device_name"],
                "has_baseline": has_baseline,
                "source": row["baseline_source"] or "",
                "baseline_captured_at": row["baseline_captured_at"] or "",
                "baseline_revision": row["baseline_revision"] or "",
                "baseline_mock": bool(row["baseline_mock"]) if has_baseline else False,
                "age_days": age_days,
                "stale": stale,
                "last_status": row["comparison_status"] or (
                    "not_checked" if has_baseline else "missing"
                ),
                "last_checked_at": row["checked_at"] or "",
                "current_revision": row["current_revision"] or "",
                "added_lines": row["added_lines"] or 0,
                "removed_lines": row["removed_lines"] or 0,
                "error": row["error"] or "",
                "comparison_mock": bool(row["comparison_mock"])
                if row["comparison_mock"] is not None else False,
            })
        counts = {
            state: sum(device["last_status"] == state for device in devices)
            for state in ("unchanged", "changed", "missing", "failed", "not_checked")
        }
        counts.update({
            "with_baseline": sum(device["has_baseline"] for device in devices),
            "stale": sum(device["stale"] for device in devices),
        })
        coverage_attention = any(
            not device["has_baseline"] or device["stale"]
            or device["last_status"] in {"failed", "not_checked"}
            for device in devices
        )
        drift = counts["changed"] > 0
        exit_code = (1 if coverage_attention else 0) | (2 if drift else 0)
        return {
            "status": "success", "count": len(devices), "max_age_days": max_age_days,
            "counts": counts, "attention": bool(exit_code), "exit_code": exit_code,
            "devices": devices,
        }

    def compare_full(self, device: str) -> dict[str, object]:
        try:
            result = {**self._build_comparison(device), "error": None}
        except MissingBaselineError as exc:
            result = {
                "status": "error", "device": device, "changed": None, "diff": "",
                "error": self.error_mapper(exc), "mock": self.mock,
                "approval_required": True,
                "snapshot_proposal": {
                    "action": "create", "device": device, "source": "running",
                    "replace": False,
                    "reason": (
                        "No baseline exists. A new capture provides current configuration data and "
                        "a starting point for future comparisons, but cannot reconstruct past state."
                    ),
                },
            }
        except Exception as exc:
            result = {
                "status": "error", "device": device, "changed": None, "diff": "",
                "error": self.error_mapper(exc), "mock": self.mock, **self._baseline_context(device),
            }
        self._record_comparison(result)
        return result

    def compare_all(self, workers: int = 4) -> dict[str, object]:
        """Compare every inventory device and return compact drift metadata only."""
        if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 16:
            raise InventoryError("Workers must be an integer from 1 to 16.")
        devices = self.inventory.list()
        if not devices:
            raise InventoryError("No devices are inventoried.")
        summaries: dict[str, dict[str, object]] = {}
        with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
            futures = {pool.submit(self.compare_full, device.name): device.name for device in devices}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    summaries[name] = self._comparison_summary(future.result())
                except Exception as exc:
                    failed = {
                        "status": "error", "device": name, "error": self.error_mapper(exc),
                        "mock": self.mock,
                    }
                    self._record_comparison(failed)
                    summaries[name] = self._comparison_summary(failed)
        results = [summaries[device.name] for device in devices]
        counts = {
            state: sum(result["status"] == state for result in results)
            for state in ("unchanged", "changed", "missing", "failed")
        }
        incomplete = counts["missing"] + counts["failed"]
        exit_code = (1 if incomplete else 0) | (2 if counts["changed"] else 0)
        return {
            "status": "success" if not incomplete else "partial",
            "complete": not incomplete,
            "counts": {"total": len(results), **counts},
            "exit_code": exit_code,
            "results": results,
            "mock": self.mock,
        }

    def compare_page(self, device: str, cursor: int, revision: str) -> dict[str, object]:
        try:
            comparison = self._build_comparison(device)
            diff = comparison.pop("diff")
            if not isinstance(cursor, int) or isinstance(cursor, bool) or not 0 <= cursor <= len(diff):
                raise InventoryError("Invalid comparison cursor.")
            if revision and revision != comparison["comparison_revision"]:
                raise InventoryError(
                    "The baseline or current configuration changed between pages; restart with cursor 0."
                )
            end = min(cursor + self.diff_page_chars, len(diff))
            result = {
                **comparison,
                "revision": comparison["comparison_revision"],
                "cursor": cursor,
                "next_cursor": None if end == len(diff) else end,
                "complete": end == len(diff),
                "output": diff[cursor:end],
                "error": None,
            }
        except MissingBaselineError as exc:
            result = {
                "status": "error", "device": device, "changed": None, "cursor": cursor,
                "next_cursor": None, "complete": False, "output": "",
                "error": self.error_mapper(exc), "mock": self.mock,
                "approval_required": True,
                "snapshot_proposal": {
                    "action": "create", "device": device, "source": "running",
                    "replace": False,
                    "reason": (
                        "No baseline exists. A new capture provides current configuration data and "
                        "a starting point for future comparisons, but cannot reconstruct past state."
                    ),
                },
            }
        except Exception as exc:
            result = {
                "status": "error", "device": device, "changed": None, "cursor": cursor,
                "next_cursor": None, "complete": False, "output": "",
                "error": self.error_mapper(exc), "mock": self.mock, **self._baseline_context(device),
            }
        if cursor == 0:
            self._record_comparison(result)
        return result
