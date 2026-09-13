import sqlite3
from datetime import datetime, timezone

import nerd_mcp.snapshots as snapshot_module
from nerd_mcp.inventory import Inventory
from nerd_mcp.snapshots import ConfigurationBaselines, normalize_configuration


def make_inventory(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text("name,host\ncore,192.0.2.1\n", encoding="utf-8")
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return inventory


class FakeNetwork:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def configuration(self, device, source):
        self.calls.append((device, source))
        return self.results.pop(0)


class MappingNetwork:
    def __init__(self, outputs):
        self.outputs = outputs

    def configuration(self, device, source):
        value = self.outputs[device]
        if isinstance(value, dict):
            return value
        return config_result(value, timestamp=f"2026-09-08T12:00:0{len(device)}+00:00")


def config_result(output, timestamp="2026-09-08T12:00:00+00:00", redactions=0):
    return {
        "status": "success", "device": "core", "source": "running",
        "timestamp": timestamp, "output": output, "redactions": redactions,
        "error": None,
    }


def test_normalization_ignores_display_metadata_and_trailing_whitespace():
    config = (
        "Building configuration...\r\nCurrent configuration : 1234 bytes\r\n"
        "! Last configuration change at 10:00 UTC Tue Sep 8 2026\r\n"
        "hostname R1   \r\ninterface Ethernet0/0\r\n"
    )
    normalized, ignored = normalize_configuration(config)
    assert normalized == "hostname R1\ninterface Ethernet0/0"
    assert ignored == 3


def test_capture_stores_one_sanitized_baseline(tmp_path):
    inventory = make_inventory(tmp_path)
    baselines = ConfigurationBaselines(inventory, mock=True)
    result = baselines.capture("core")
    assert result["status"] == "success"
    assert result["replaced"] is False
    assert result["baseline"]["redactions"] == 4
    stored = baselines.get_full("core")
    assert "hostname mock-device" in stored["configuration"]
    assert "mock-enable-secret" not in stored["configuration"]
    with sqlite3.connect(inventory.path) as db:
        raw = db.execute(
            "SELECT configuration FROM configuration_baselines WHERE device_name='core'"
        ).fetchone()[0]
    assert "mock-enable-secret" not in raw


def test_existing_baseline_requires_replace_without_contacting_device(tmp_path):
    inventory = make_inventory(tmp_path)
    first = FakeNetwork([config_result("hostname R1")])
    assert ConfigurationBaselines(inventory, network=first).capture("core")["status"] == "success"
    second = FakeNetwork([config_result("hostname CHANGED")])
    result = ConfigurationBaselines(inventory, network=second).capture("core")
    assert result["status"] == "error"
    assert "--replace" in result["error"]
    assert second.calls == []
    assert ConfigurationBaselines(inventory).get_full("core")["configuration"] == "hostname R1"


def test_replace_updates_the_single_row(tmp_path):
    inventory = make_inventory(tmp_path)
    network = FakeNetwork([
        config_result("hostname R1", "2026-09-08T12:00:00+00:00"),
        config_result("hostname R2", "2026-09-08T13:00:00+00:00"),
    ])
    baselines = ConfigurationBaselines(inventory, network=network)
    baselines.capture("core")
    replaced = baselines.capture("core", replace=True)
    assert replaced["status"] == "success" and replaced["replaced"] is True
    assert baselines.get_full("core")["configuration"] == "hostname R2"
    assert baselines.list()["count"] == 1


def test_failed_replace_preserves_previous_baseline(tmp_path):
    inventory = make_inventory(tmp_path)
    good = FakeNetwork([config_result("hostname R1")])
    baselines = ConfigurationBaselines(inventory, network=good)
    assert baselines.capture("core")["status"] == "success"
    failed = FakeNetwork([{
        "status": "error", "error": "SSH connection failed.", "output": "",
        "timestamp": "2026-09-08T13:00:00+00:00", "redactions": 0,
    }])
    result = ConfigurationBaselines(inventory, network=failed).capture("core", replace=True)
    assert result["status"] == "error"
    assert ConfigurationBaselines(inventory).get_full("core")["configuration"] == "hostname R1"


def test_compare_ignores_volatile_changes_and_reports_real_diff(tmp_path):
    inventory = make_inventory(tmp_path)
    network = FakeNetwork([
        config_result("Building configuration...\nCurrent configuration : 10 bytes\nhostname R1"),
        config_result("Building configuration...\nCurrent configuration : 99 bytes\nhostname R1"),
        config_result("hostname R1\ninterface Ethernet0/0\n shutdown"),
    ])
    baselines = ConfigurationBaselines(inventory, network=network)
    baselines.capture("core")
    unchanged = baselines.compare_full("core")
    assert unchanged["changed"] is False
    assert unchanged["diff"] == ""
    changed = baselines.compare_full("core")
    assert changed["changed"] is True
    assert changed["added_lines"] == 2 and changed["removed_lines"] == 0
    assert "+interface Ethernet0/0" in changed["diff"]


def test_baseline_and_diff_pages_are_revision_checked(tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path)
    monkeypatch.setattr(snapshot_module, "BASELINE_PAGE_CHARS", 8)
    monkeypatch.setattr(snapshot_module, "DIFF_PAGE_CHARS", 20)
    network = FakeNetwork([
        config_result("hostname R1\ninterface Ethernet0/0"),
        config_result("hostname R2\ninterface Ethernet0/0"),
        config_result("hostname R2\ninterface Ethernet0/0"),
    ])
    baselines = ConfigurationBaselines(inventory, network=network)
    baselines.capture("core")
    page = baselines.get_page("core", 0, "")
    assert page["complete"] is False and page["next_cursor"] == 8
    bad_page = baselines.get_page("core", page["next_cursor"], "wrong")
    assert bad_page["status"] == "error" and "changed between pages" in bad_page["error"]
    diff = baselines.compare_page("core", 0, "")
    assert diff["complete"] is False
    assert diff["revision"] == diff["comparison_revision"]
    bad_diff = baselines.compare_page("core", diff["next_cursor"], "wrong")
    assert bad_diff["status"] == "error" and "changed between pages" in bad_diff["error"]


def test_missing_unknown_remove_cascade_and_size_limit(tmp_path, monkeypatch):
    inventory = make_inventory(tmp_path)
    baselines = ConfigurationBaselines(inventory, mock=True)
    assert baselines.get_page("core", 0, "")["status"] == "error"
    comparison = baselines.compare_page("core", 0, "")
    assert comparison["approval_required"] is True
    assert comparison["snapshot_proposal"] == {
        "action": "create", "device": "core", "source": "running", "replace": False,
        "reason": (
            "No baseline exists. A new capture provides current configuration data and "
            "a starting point for future comparisons, but cannot reconstruct past state."
        ),
    }
    assert baselines.capture("missing")["status"] == "error"
    monkeypatch.setattr(snapshot_module, "MAX_BASELINE_CHARS", 4)
    oversized = ConfigurationBaselines(
        inventory, network=FakeNetwork([config_result("hostname R1")])
    ).capture("core")
    assert oversized["status"] == "error" and "character baseline limit" in oversized["error"]
    monkeypatch.setattr(snapshot_module, "MAX_BASELINE_CHARS", 5_000_000)
    assert baselines.capture("core")["status"] == "success"
    assert inventory.remove("core") is True
    with sqlite3.connect(inventory.path) as db:
        count = db.execute("SELECT COUNT(*) FROM configuration_baselines").fetchone()[0]
    assert count == 0


def test_fleet_compare_classifies_drift_missing_and_stores_metadata_only(tmp_path):
    inventory = make_inventory(tmp_path)
    source = tmp_path / "more.csv"
    source.write_text(
        "name,host\nedge,192.0.2.2\nnew,192.0.2.3\n", encoding="utf-8"
    )
    inventory.import_file(source)
    network = MappingNetwork({
        "core": "hostname core", "edge": "hostname edge", "new": "hostname new",
    })
    baselines = ConfigurationBaselines(inventory, network=network)
    assert baselines.capture("core")["status"] == "success"
    assert baselines.capture("edge")["status"] == "success"
    network.outputs["edge"] = "hostname edge\ninterface Ethernet0/1\n shutdown"
    result = baselines.compare_all(workers=2)
    assert result["counts"] == {
        "total": 3, "unchanged": 1, "changed": 1, "missing": 1, "failed": 0,
    }
    assert result["exit_code"] == 3 and result["complete"] is False
    assert [row["device"] for row in result["results"]] == ["core", "edge", "new"]
    assert all("diff" not in row and "configuration" not in row for row in result["results"])
    status = baselines.status()
    assert status["counts"]["unchanged"] == 1
    assert status["counts"]["changed"] == 1
    assert status["counts"]["missing"] == 1
    with sqlite3.connect(inventory.path) as db:
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(configuration_comparison_status)")
        }
        rows = db.execute(
            "SELECT device_name, status FROM configuration_comparison_status ORDER BY device_name"
        ).fetchall()
    assert "configuration" not in columns and "diff" not in columns
    assert rows == [("core", "unchanged"), ("edge", "changed"), ("new", "missing")]


def test_fleet_compare_exit_codes_and_replacement_clears_status(tmp_path):
    inventory = make_inventory(tmp_path)
    network = MappingNetwork({"core": "hostname core"})
    baselines = ConfigurationBaselines(inventory, network=network)
    baselines.capture("core")
    assert baselines.compare_all(1)["exit_code"] == 0
    network.outputs["core"] = "hostname changed"
    assert baselines.compare_all(1)["exit_code"] == 2
    failed = {
        "status": "error", "error": "SSH connection failed.", "output": "",
        "timestamp": "2026-09-08T13:00:00+00:00", "redactions": 0,
    }
    network.outputs["core"] = failed
    assert baselines.compare_all(1)["exit_code"] == 1
    network.outputs["core"] = "hostname replacement"
    assert baselines.capture("core", replace=True)["status"] == "success"
    assert baselines.status()["devices"][0]["last_status"] == "not_checked"


def test_fleet_compare_validates_workers_and_requires_inventory(tmp_path):
    inventory = make_inventory(tmp_path)
    baselines = ConfigurationBaselines(inventory, mock=True)
    for workers in (0, 17, True):
        try:
            baselines.compare_all(workers)
        except ValueError as exc:
            assert "1 to 16" in str(exc)
        else:
            raise AssertionError("invalid worker count was accepted")
    inventory.remove("core")
    try:
        baselines.compare_all(1)
    except ValueError as exc:
        assert "No devices" in str(exc)
    else:
        raise AssertionError("empty inventory was accepted")


def test_comparison_rejects_mock_and_live_mode_mismatch(tmp_path):
    inventory = make_inventory(tmp_path)
    assert ConfigurationBaselines(inventory, mock=True).capture("core")["status"] == "success"
    result = ConfigurationBaselines(inventory, mock=False).compare_full("core")
    assert result["status"] == "error"
    assert "same mock or live mode" in result["error"]
    assert result["source"] == "running"
    assert result["baseline_revision"]


def test_capture_all_creates_only_missing_baselines_and_skips_existing(tmp_path):
    inventory = make_inventory(tmp_path)
    source = tmp_path / "more.csv"
    source.write_text("name,host\nedge,192.0.2.2\nnew,192.0.2.3\n", encoding="utf-8")
    inventory.import_file(source)
    network = MappingNetwork({
        "core": "hostname core", "edge": "hostname edge", "new": "hostname new",
    })
    baselines = ConfigurationBaselines(inventory, network=network)
    assert baselines.capture("core")["status"] == "success"
    result = baselines.capture_all("running", workers=2)
    assert result["counts"] == {"total": 3, "created": 2, "existing": 1, "failed": 0}
    assert result["exit_code"] == 0
    assert [row["status"] for row in result["results"]] == ["existing", "created", "created"]
    network.outputs.clear()
    second = baselines.capture_all("running", workers=2)
    assert second["counts"]["created"] == 0
    assert second["counts"]["existing"] == 3


def test_capture_all_reports_failures_without_removing_successes(tmp_path):
    inventory = make_inventory(tmp_path)
    failed = {
        "status": "error", "error": "SSH connection failed.", "output": "",
        "timestamp": "2026-09-08T13:00:00+00:00", "redactions": 0,
    }
    result = ConfigurationBaselines(
        inventory, network=MappingNetwork({"core": failed})
    ).capture_all(workers=1)
    assert result["status"] == "partial"
    assert result["counts"]["failed"] == 1 and result["exit_code"] == 1
    assert ConfigurationBaselines(inventory).list()["count"] == 0


def test_refresh_all_replaces_existing_and_creates_missing_with_expected_sources(tmp_path):
    inventory = make_inventory(tmp_path)
    source = tmp_path / "more.csv"
    source.write_text("name,host\nedge,192.0.2.2\nnew,192.0.2.3\n", encoding="utf-8")
    inventory.import_file(source)
    network = MappingNetwork({
        "core": "hostname core-old", "edge": "hostname edge-old", "new": "hostname new",
    })
    baselines = ConfigurationBaselines(inventory, network=network)
    assert baselines.capture("core", "running")["status"] == "success"
    assert baselines.capture("edge", "startup")["status"] == "success"
    network.outputs.update({"core": "hostname core-new", "edge": "hostname edge-new"})

    result = baselines.refresh_all(workers=2)

    assert result["counts"] == {"total": 3, "refreshed": 2, "created": 1, "failed": 0}
    assert result["exit_code"] == 0 and result["source"] == "preserve"
    assert [row["status"] for row in result["results"]] == ["refreshed", "refreshed", "created"]
    assert [row["source"] for row in result["results"]] == ["running", "startup", "running"]
    assert baselines.get_full("core")["configuration"] == "hostname core-new"
    assert baselines.get_full("edge")["configuration"] == "hostname edge-new"
    assert baselines.get_full("new")["configuration"] == "hostname new"


def test_refresh_all_failure_preserves_previous_baseline(tmp_path):
    inventory = make_inventory(tmp_path)
    network = MappingNetwork({"core": "hostname core-old"})
    baselines = ConfigurationBaselines(inventory, network=network)
    assert baselines.capture("core")["status"] == "success"
    network.outputs["core"] = {
        "status": "error", "error": "SSH connection failed.", "output": "",
        "timestamp": "2026-09-08T13:00:00+00:00", "redactions": 0,
    }

    result = baselines.refresh_all(workers=1)

    assert result["status"] == "partial" and result["exit_code"] == 1
    assert result["counts"]["failed"] == 1
    assert baselines.get_full("core")["configuration"] == "hostname core-old"


def test_refresh_all_source_override_and_validation(tmp_path):
    inventory = make_inventory(tmp_path)
    network = MappingNetwork({"core": "hostname core"})
    baselines = ConfigurationBaselines(inventory, network=network)
    result = baselines.refresh_all("startup", workers=1)
    assert result["source"] == "startup"
    assert result["results"][0]["source"] == "startup"
    for source, workers in (("candidate", 1), (None, 0), (None, 17), (None, True)):
        try:
            baselines.refresh_all(source, workers)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid refresh arguments were accepted")


def test_baseline_status_tracks_age_comparison_state_and_exit_bits(tmp_path):
    inventory = make_inventory(tmp_path)
    network = MappingNetwork({"core": "hostname core"})
    baselines = ConfigurationBaselines(inventory, network=network)
    baselines.capture("core")
    fresh_time = datetime(2026, 9, 8, 13, tzinfo=timezone.utc)
    never_checked = baselines.status(30, now=fresh_time)
    assert never_checked["devices"][0]["age_days"] == 0
    assert never_checked["devices"][0]["last_status"] == "not_checked"
    assert never_checked["exit_code"] == 1
    assert baselines.compare_all(1)["exit_code"] == 0
    clean = baselines.status(30, now=fresh_time)
    assert clean["exit_code"] == 0 and clean["attention"] is False
    stale = baselines.status(1, now=datetime(2026, 9, 10, 13, tzinfo=timezone.utc))
    assert stale["devices"][0]["age_days"] == 2
    assert stale["devices"][0]["stale"] is True
    assert stale["exit_code"] == 1
    network.outputs["core"] = "hostname changed"
    baselines.compare_all(1)
    stale_drift = baselines.status(1, now=datetime(2026, 9, 10, 13, tzinfo=timezone.utc))
    assert stale_drift["exit_code"] == 3


def test_baseline_status_validates_age_threshold(tmp_path):
    baselines = ConfigurationBaselines(make_inventory(tmp_path), mock=True)
    for value in (-1, 36_501, True):
        try:
            baselines.status(value)
        except ValueError as exc:
            assert "0 to 36500" in str(exc)
        else:
            raise AssertionError("invalid maximum age was accepted")
