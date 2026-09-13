import pytest
import sqlite3
from openpyxl import Workbook

from nerd_mcp.inventory import Inventory, InventoryError


@pytest.fixture
def inventory(tmp_path):
    return Inventory(tmp_path / "devices.db")


def csv_file(tmp_path, text):
    path = tmp_path / "input.csv"
    path.write_text(text, encoding="utf-8-sig")
    return path


def test_defaults_bom_and_identical(inventory, tmp_path):
    path = csv_file(tmp_path, "name,host\ncore,192.0.2.1\n")
    assert inventory.import_csv(path) == {"added": 1, "updated": 0, "unchanged": 0}
    assert inventory.get("core").port == 22
    assert inventory.get("core").credential_profile == "default"
    assert inventory.import_csv(path)["unchanged"] == 1


def test_device_names_are_resolved_case_insensitively(inventory, tmp_path):
    inventory.import_csv(csv_file(tmp_path, "name,host\nSW1,192.0.2.1\n"))
    assert inventory.get("sw1").name == "SW1"
    inventory.update_facts("sW1", {"serial_number": "ABC123"})
    assert inventory.get("SW1").serial_number == "ABC123"
    assert inventory.remove("sw1") is True


def test_import_rejects_case_variant_duplicate_names_atomically(inventory, tmp_path):
    with pytest.raises(InventoryError, match="duplicate device name"):
        inventory.import_csv(csv_file(
            tmp_path, "name,host\nSW1,192.0.2.1\nsw1,192.0.2.2\n"
        ))
    assert inventory.list() == []


def test_import_case_variant_matches_existing_canonical_record(inventory, tmp_path):
    inventory.import_csv(csv_file(tmp_path, "name,host\nSW1,192.0.2.1\n"))
    update = csv_file(tmp_path, "name,host\nsw1,192.0.2.2\n")
    assert inventory.import_csv(update, update=True)["updated"] == 1
    devices = inventory.list()
    assert len(devices) == 1 and devices[0].name == "SW1"
    assert devices[0].host == "192.0.2.2"


@pytest.mark.parametrize("text", [
    "host\n192.0.2.1\n",
    "name,host,port\ncore,192.0.2.1,0\n",
    "name,host,port\ncore,192.0.2.1,65536\n",
    "name,host,port\ncore,192.0.2.1,abc\n",
    "name,host\ncore,192.0.2.1\ncore,192.0.2.2\n",
    "name,host\ncore,192.0.2.1\nbad,999.999.999.999\n",
    "name,host\ncore,router;reload\n",
    "name,host,password\ncore,192.0.2.1,secret\n",
    "name,host\ncore\n",
    "name,host,credential_profile\ncore,192.0.2.1,a-b\n",
    'name,host\ncore,"unclosed\n',
])
def test_invalid_is_atomic(inventory, tmp_path, text):
    with pytest.raises(InventoryError):
        inventory.import_csv(csv_file(tmp_path, text))
    assert inventory.list() == []


def test_conflict_rolls_back_and_update(inventory, tmp_path):
    inventory.import_csv(csv_file(tmp_path, "name,host\ncore,192.0.2.1\n"))
    path = csv_file(tmp_path, "name,host\nnew,192.0.2.3\ncore,192.0.2.2\n")
    with pytest.raises(InventoryError, match="Row 3"):
        inventory.import_csv(path)
    assert [d.name for d in inventory.list()] == ["core"]
    assert inventory.get("core").host == "192.0.2.1"
    assert inventory.import_csv(path, update=True) == {"added": 1, "updated": 1, "unchanged": 0}
    assert inventory.get("core").host == "192.0.2.2"
    assert inventory.remove("new")
    assert not inventory.remove("new")


def test_multiple_row_errors(inventory, tmp_path):
    with pytest.raises(InventoryError) as error:
        inventory.import_csv(csv_file(tmp_path, "name,host\n,192.0.2.1\nbad,not a host\n"))
    assert "Row 2" in str(error.value) and "Row 3" in str(error.value)


def test_expanded_csv_and_friendly_headers(inventory, tmp_path):
    path = csv_file(tmp_path, """name,host,Device Hostname,Location,Street Address,City,State,ZipCode,Country,Serial Number,Model,Device Type,Vendor,Platform
fw1,192.0.2.10,FW-EXAMPLE,Example Data Center,100 Example Ave,Example City,NC,28202,usa,FG123,FG-100F,firewall,Fortinet,FortiOS
""")
    assert inventory.import_file(path)["added"] == 1
    device = inventory.get("fw1")
    assert device.device_hostname == "FW-EXAMPLE"
    assert device.street_address == "100 Example Ave"
    assert device.zip_code == "28202"
    assert device.country == "USA"
    assert device.serial_number == "FG123"
    assert device.device_type == "firewall"
    assert device.location_source == "csv"


def test_excel_import_and_search(inventory, tmp_path):
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["name", "host", "Location", "City", "State", "Country", "Device Type"])
    sheet.append(["r1", "192.0.2.1", "Example Branch", "Example City", "NC", "USA", "router"])
    sheet.append(["fw1", "192.0.2.2", "Sample Data Center", "Sample City", "TX", "USA", "firewall"])
    path = tmp_path / "inventory.xlsx"
    workbook.save(path)
    workbook.close()
    assert inventory.import_file(path) == {"added": 2, "updated": 0, "unchanged": 0}
    assert [d.name for d in inventory.search(city="Example City")] == ["r1"]
    assert [d.name for d in inventory.search(location="Sample City", device_type="firewall")] == ["fw1"]
    assert [d.name for d in inventory.search(state="tx")] == ["fw1"]


def test_legacy_database_migrates_without_losing_device(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE devices (name TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL, credential_profile TEXT NOT NULL)")
        db.execute("INSERT INTO devices VALUES ('core', '192.0.2.1', 22, 'default')")
    device = Inventory(path).get("core")
    assert device.host == "192.0.2.1"
    assert device.vendor == "Cisco"
    assert device.city == ""


def test_import_omitted_metadata_preserves_discovered_facts(inventory, tmp_path):
    inventory.import_file(csv_file(tmp_path, "name,host\ncore,192.0.2.1\n"))
    inventory.update_facts("core", {
        "device_hostname": "CORE-RTR", "serial_number": "ABC123",
        "model": "C8000V", "location": "Device room",
    })
    assert inventory.import_file(
        csv_file(tmp_path, "name,host\ncore,192.0.2.1\n"), update=True
    )["unchanged"] == 1
    assert inventory.get("core").serial_number == "ABC123"


def test_csv_location_has_precedence_over_device_location(inventory, tmp_path):
    inventory.import_file(csv_file(
        tmp_path, "name,host,location\ncore,192.0.2.1,Example Office\n"
    ))
    inventory.update_facts("core", {
        "device_hostname": "CORE", "serial_number": "ABC", "model": "C9300",
        "location": "Device configured location",
    })
    device = inventory.get("core")
    assert device.location == "Example Office"
    assert device.location_source == "csv"
    assert device.facts_updated_at


@pytest.mark.parametrize("country", ["US", "UNITED STATES", "12A"])
def test_country_requires_alpha3(inventory, tmp_path, country):
    with pytest.raises(InventoryError, match="three-letter"):
        inventory.import_file(csv_file(
            tmp_path, f"name,host,country\ncore,192.0.2.1,{country}\n"
        ))
