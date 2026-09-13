import json

from nerd_mcp.application.diagnosis import is_diagnostic_request
from nerd_mcp.bootstrap import build_application
from nerd_mcp.inventory import Inventory


def make_app(tmp_path):
    source = tmp_path / "devices.csv"
    source.write_text(
        "name,host,vendor,platform\nR1,192.0.2.1,Cisco,IOS/IOS-XE\n"
        "R2,192.0.2.2,Cisco,IOS/IOS-XE\n", encoding="utf-8",
    )
    inventory = Inventory(tmp_path / "devices.db")
    inventory.import_file(source)
    return build_application(inventory, mock=True)


def test_diagnostic_intent_and_inventory_target_extraction(tmp_path):
    app = make_app(tmp_path)
    assert is_diagnostic_request("Diagnose the BGP problem between R1 and R2")
    assert is_diagnostic_request(
        "Examine the BGP configuration on R1 and give me recommendations"
    )
    assert not is_diagnostic_request("Tell me about R1")
    assert app.diagnoses.named_devices("R2 cannot peer with R1") == ("R1", "R2")


def test_high_confidence_diagnosis_creates_device_scoped_plan_and_persists(tmp_path):
    app = make_app(tmp_path)

    def interpret(_question, _devices, evidence):
        assert {row.device for row in evidence} == {"R1", "R2"}
        assert {row.kind for row in evidence} >= {"configuration", "bgp_status"}
        return {
            "root_cause": "R1 has the wrong remote AS.", "confidence": "high",
            "evidence": ["R1 expects AS 65002 while R2 uses AS 65001."],
            "incorrect_configuration": [{
                "device": "R1",
                "lines": ["neighbor 2.2.2.2 remote-as 65002"],
            }],
            "recommendation": "Make R1's peer an iBGP neighbor.",
            "operations": [{
                "device": "R1", "kind": "bgp_neighbor",
                "values_json": json.dumps({
                    "neighbor": "2.2.2.2", "remote_as": 65001,
                    "update_source": "Loopback0",
                }),
            }], "next_steps": [],
        }

    app.diagnoses.interpreter = interpret
    report = app.diagnoses.diagnose("Diagnose the BGP problem between R1 and R2")
    assert report["state"] == "prepared"
    assert report["change_id"].startswith("CHG-")
    assert report["plan"]["devices"][0]["commands"]
    assert report["plan"]["request"]["operations"][0]["values"]["local_as"] == 65001
    assert report["root_cause"]["incorrect_configuration"][0]["device"] == "R1"
    assert report["plan"]["devices"][1]["commands"] == ()
    stored = app.diagnosis_repository.get(report["diagnosis_id"])
    assert stored["change_id"] == report["change_id"]
    assert "mock:R1" not in json.dumps(stored)


def test_uncertain_diagnosis_never_creates_apply_plan(tmp_path):
    app = make_app(tmp_path)
    app.diagnoses.interpreter = lambda *_args: {
        "root_cause": "Evidence supports multiple possible causes.", "confidence": "medium",
        "evidence": ["The peer is idle."], "recommendation": "Collect TCP evidence.",
        "operations": [], "next_steps": ["Check TCP port 179."],
    }
    report = app.diagnoses.diagnose("Troubleshoot BGP on R1", ("R1",))
    assert report["state"] == "inconclusive" and report["change_id"] is None


def test_unverified_incorrect_configuration_blocks_apply(tmp_path):
    app = make_app(tmp_path)
    app.diagnoses.interpreter = lambda *_args: {
        "root_cause": "A bad BGP line exists.", "confidence": "high",
        "evidence": ["The configuration is wrong."],
        "incorrect_configuration": [{
            "device": "R1", "lines": ["neighbor 203.0.113.9 remote-as 99999"],
        }],
        "recommendation": "Correct the neighbor.",
        "operations": [{
            "device": "R1", "kind": "bgp_neighbor",
            "values_json": json.dumps({
                "neighbor": "2.2.2.2", "remote_as": 65001,
                "update_source": "Loopback0",
            }),
        }],
        "next_steps": [],
    }
    report = app.diagnoses.diagnose("Diagnose BGP on R1", ("R1",))
    assert report["state"] == "inconclusive"
    assert report["change_id"] is None
    assert "not found in current live evidence" in report["planning_error"]


def test_diagnosis_decisions_are_durable(tmp_path):
    app = make_app(tmp_path)
    app.diagnoses.interpreter = lambda *_args: {
        "root_cause": "No safe correction is established.", "confidence": "low",
        "evidence": [], "recommendation": "Continue diagnostics.",
        "operations": [], "next_steps": [],
    }
    report = app.diagnoses.diagnose("Diagnose a problem on R1", ("R1",))
    ignored = app.diagnoses.decide(report["diagnosis_id"], "ignored")
    assert ignored["state"] == "ignored" and ignored["decision"] == "ignored"
