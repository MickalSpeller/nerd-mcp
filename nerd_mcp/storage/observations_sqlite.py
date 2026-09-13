"""SQLite storage for current MAC, ARP, neighbor, and interface observations."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict

from ..domain.models import NeighborObservation
from ..domain.normalization import interface_key as _interface_key
from ..domain.ports import InventoryPort


class ObservationRepository:
    def __init__(self, inventory: InventoryPort):
        self.inventory = inventory

    @contextmanager
    def connect(self):
        with self.inventory.connect() as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("""CREATE TABLE IF NOT EXISTS mac_scans (
                device_name TEXT PRIMARY KEY REFERENCES devices(name) ON DELETE CASCADE,
                last_attempt_at TEXT NOT NULL, observations_at TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL, error TEXT, mac_count INTEGER NOT NULL DEFAULT 0,
                arp_count INTEGER NOT NULL DEFAULT 0, neighbor_count INTEGER NOT NULL DEFAULT 0,
                mock INTEGER NOT NULL DEFAULT 0)""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(mac_scans)")}
            if "mock" not in columns:
                db.execute("ALTER TABLE mac_scans ADD COLUMN mock INTEGER NOT NULL DEFAULT 0")
            db.execute("""CREATE TABLE IF NOT EXISTS topology_scans (
                device_name TEXT PRIMARY KEY REFERENCES devices(name) ON DELETE CASCADE,
                last_attempt_at TEXT NOT NULL, observations_at TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL, error TEXT, neighbor_count INTEGER NOT NULL DEFAULT 0,
                mock INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS mac_observations (
                device_name TEXT NOT NULL REFERENCES devices(name) ON DELETE CASCADE,
                mac TEXT NOT NULL, vlan TEXT NOT NULL, interface TEXT NOT NULL,
                interface_key TEXT NOT NULL, entry_type TEXT NOT NULL, role TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (device_name, mac, vlan, interface))""")
            db.execute("CREATE INDEX IF NOT EXISTS mac_observations_mac ON mac_observations(mac)")
            db.execute("""CREATE TABLE IF NOT EXISTS arp_observations (
                device_name TEXT NOT NULL REFERENCES devices(name) ON DELETE CASCADE,
                mac TEXT NOT NULL, ip TEXT NOT NULL, interface TEXT NOT NULL, vrf TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (device_name, mac, ip, interface, vrf))""")
            db.execute("CREATE INDEX IF NOT EXISTS arp_observations_mac ON arp_observations(mac)")
            db.execute("CREATE INDEX IF NOT EXISTS arp_observations_ip ON arp_observations(ip)")
            db.execute("""CREATE TABLE IF NOT EXISTS mac_neighbors (
                device_name TEXT NOT NULL REFERENCES devices(name) ON DELETE CASCADE,
                interface TEXT NOT NULL, interface_key TEXT NOT NULL, neighbor TEXT NOT NULL,
                neighbor_address TEXT NOT NULL DEFAULT '', remote_interface TEXT NOT NULL,
                protocol TEXT NOT NULL, observed_at TEXT NOT NULL,
                PRIMARY KEY (device_name, interface, neighbor, protocol))""")
            neighbor_columns = {row["name"] for row in db.execute("PRAGMA table_info(mac_neighbors)")}
            if "neighbor_address" not in neighbor_columns:
                db.execute(
                    "ALTER TABLE mac_neighbors ADD COLUMN neighbor_address TEXT NOT NULL DEFAULT ''"
                )
            db.execute("""CREATE TABLE IF NOT EXISTS mac_interface_health (
                device_name TEXT NOT NULL REFERENCES devices(name) ON DELETE CASCADE,
                interface TEXT NOT NULL, interface_key TEXT NOT NULL, status TEXT NOT NULL,
                protocol TEXT NOT NULL, description TEXT NOT NULL, input_errors INTEGER NOT NULL,
                crc_errors INTEGER NOT NULL, output_errors INTEGER NOT NULL, speed TEXT NOT NULL,
                duplex TEXT NOT NULL, observed_at TEXT NOT NULL,
                PRIMARY KEY (device_name, interface))""")
            yield db

    def prepare(self) -> None:
        """Create or upgrade observation tables before concurrent collection."""
        with self.connect():
            pass

    def record_failure(self, device: str, timestamp: str, status: str, error: str) -> None:
        with self.connect() as db:
            db.execute("""INSERT INTO mac_scans
                (device_name, last_attempt_at, status, error) VALUES (?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at, status=excluded.status, error=excluded.error""",
                (device, timestamp, status, error))

    def record_topology_failure(self, device: str, timestamp: str,
                                status: str, error: str) -> None:
        with self.connect() as db:
            db.execute("""INSERT INTO topology_scans
                (device_name, last_attempt_at, status, error) VALUES (?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at, status=excluded.status,
                error=excluded.error""", (device, timestamp, status, error))

    def replace_neighbors(self, device: str, timestamp: str, status: str,
                          error: str | None, neighbors: list[dict],
                          mock: bool = False) -> None:
        """Atomically replace topology rows without changing MAC/ARP freshness."""
        neighbors = [asdict(row) if isinstance(row, NeighborObservation) else row
                     for row in neighbors]
        with self.connect() as db:
            db.execute("DELETE FROM mac_neighbors WHERE device_name = ?", (device,))
            db.executemany("""INSERT INTO mac_neighbors
                (device_name, interface, interface_key, neighbor, neighbor_address,
                 remote_interface, protocol, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", [
                (device, row["interface"], _interface_key(row["interface"]), row["neighbor"],
                 row.get("neighbor_address", ""), row["remote_interface"], row["protocol"], timestamp)
                for row in neighbors
            ])
            db.execute("""INSERT INTO topology_scans
                (device_name, last_attempt_at, observations_at, status, error,
                 neighbor_count, mock) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at,
                observations_at=excluded.observations_at, status=excluded.status,
                error=excluded.error, neighbor_count=excluded.neighbor_count,
                mock=excluded.mock""",
                (device, timestamp, timestamp, status, error, len(neighbors), int(mock)))

    def replace(self, device: str, timestamp: str, status: str, error: str | None,
                macs: list[dict], arps: list[dict], neighbors: list[dict],
                interfaces: list[dict], mock: bool = False) -> None:
        macs = [asdict(row) if not isinstance(row, dict) else row for row in macs]
        arps = [asdict(row) if not isinstance(row, dict) else row for row in arps]
        neighbors = [asdict(row) if not isinstance(row, dict) else row for row in neighbors]
        interfaces = [asdict(row) if not isinstance(row, dict) else row for row in interfaces]
        with self.connect() as db:
            for table in ("mac_observations", "arp_observations", "mac_neighbors", "mac_interface_health"):
                db.execute(f"DELETE FROM {table} WHERE device_name = ?", (device,))
            db.executemany("""INSERT INTO mac_observations
                (device_name, mac, vlan, interface, interface_key, entry_type, role, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", [
                (device, row["mac"], row["vlan"], row["interface"], _interface_key(row["interface"]),
                 row["entry_type"], row["role"], timestamp) for row in macs
            ])
            db.executemany("""INSERT INTO arp_observations
                (device_name, mac, ip, interface, vrf, observed_at) VALUES (?, ?, ?, ?, ?, ?)""", [
                (device, row["mac"], row["ip"], row["interface"], row["vrf"], timestamp) for row in arps
            ])
            db.executemany("""INSERT INTO mac_neighbors
                (device_name, interface, interface_key, neighbor, neighbor_address,
                 remote_interface, protocol, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", [
                (device, row["interface"], _interface_key(row["interface"]), row["neighbor"],
                 row.get("neighbor_address", ""), row["remote_interface"], row["protocol"], timestamp)
                for row in neighbors
            ])
            db.executemany("""INSERT INTO mac_interface_health
                (device_name, interface, interface_key, status, protocol, description, input_errors,
                 crc_errors, output_errors, speed, duplex, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", [
                (device, row["interface"], _interface_key(row["interface"]), row["status"],
                 row["protocol"], row["description"], row["input_errors"], row["crc_errors"],
                 row["output_errors"], row["speed"], row["duplex"], timestamp) for row in interfaces
            ])
            db.execute("""INSERT INTO mac_scans
                (device_name, last_attempt_at, observations_at, status, error, mac_count, arp_count,
                 neighbor_count, mock)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
                observations_at=excluded.observations_at, status=excluded.status, error=excluded.error,
                mac_count=excluded.mac_count, arp_count=excluded.arp_count,
                neighbor_count=excluded.neighbor_count, mock=excluded.mock""",
                (device, timestamp, timestamp, status, error, len(macs), len(arps), len(neighbors), int(mock)))
            db.execute("""INSERT INTO topology_scans
                (device_name, last_attempt_at, observations_at, status, error,
                 neighbor_count, mock) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_name) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at,
                observations_at=excluded.observations_at, status=excluded.status,
                error=excluded.error, neighbor_count=excluded.neighbor_count,
                mock=excluded.mock""",
                (device, timestamp, timestamp, status, error, len(neighbors), int(mock)))

    def topology_snapshot(
        self,
    ) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
        """Load current neighbor rows and their effective collection status."""
        with self.connect() as db:
            observations = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM mac_neighbors "
                    "ORDER BY device_name, interface, neighbor, protocol"
                )
            ]
            legacy_scans = {
                row["device_name"]: dict(row)
                for row in db.execute("SELECT * FROM mac_scans")
            }
            topology_scans = {
                row["device_name"]: dict(row)
                for row in db.execute("SELECT * FROM topology_scans")
            }
        return observations, {**legacy_scans, **topology_scans}

    def mac_lookup_rows(self, mac: str) -> dict[str, object]:
        """Load persisted rows used to locate one normalized MAC address."""
        with self.connect() as db:
            scans = {
                row["device_name"]: dict(row)
                for row in db.execute("SELECT * FROM mac_scans")
            }
            matches = [
                dict(row)
                for row in db.execute(
                    """SELECT m.*, d.device_hostname, d.location,
                    h.status AS interface_status, h.protocol AS line_protocol,
                    h.description, h.input_errors, h.crc_errors,
                    h.output_errors, h.speed, h.duplex
                    FROM mac_observations m JOIN devices d ON d.name = m.device_name
                    LEFT JOIN mac_interface_health h ON h.device_name = m.device_name
                        AND h.interface_key = m.interface_key
                    WHERE m.mac = ?""",
                    (mac,),
                )
            ]
            arps = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM arp_observations WHERE mac = ? "
                    "ORDER BY device_name, ip",
                    (mac,),
                )
            ]
            neighbors = [dict(row) for row in db.execute("SELECT * FROM mac_neighbors")]
        return {"scans": scans, "matches": matches, "arps": arps,
                "neighbors": neighbors}

    def arp_lookup_rows(self, ip_address: str) -> dict[str, object]:
        """Load persisted rows used to resolve one normalized IPv4 address."""
        with self.connect() as db:
            scans = {
                row["device_name"]: dict(row)
                for row in db.execute("SELECT * FROM mac_scans")
            }
            arps = [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM arp_observations WHERE ip = ?
                       ORDER BY device_name, mac, interface, vrf""",
                    (ip_address,),
                )
            ]
        return {"scans": scans, "arps": arps}

    def interface_lookup_rows(self, device: str) -> dict[str, object]:
        """Load persisted rows used to inspect one device interface."""
        with self.connect() as db:
            scan_row = db.execute(
                "SELECT * FROM mac_scans WHERE device_name = ?", (device,)
            ).fetchone()
            macs = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM mac_observations WHERE device_name = ?", (device,)
                )
            ]
            arps = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM arp_observations WHERE device_name = ?", (device,)
                )
            ]
            health = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM mac_interface_health WHERE device_name = ?",
                    (device,),
                )
            ]
        return {
            "scan": dict(scan_row) if scan_row else None,
            "macs": macs,
            "arps": arps,
            "health": health,
        }

    def device_mac_rows(self, device: str) -> dict[str, object]:
        """Load one device's persisted scan, MAC, and ARP observations."""
        with self.connect() as db:
            scan_row = db.execute(
                "SELECT * FROM mac_scans WHERE device_name = ?", (device,)
            ).fetchone()
            macs = [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM mac_observations WHERE device_name = ?
                       ORDER BY interface_key, vlan, mac, entry_type""",
                    (device,),
                )
            ]
            arps = [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM arp_observations WHERE device_name = ?
                       ORDER BY mac, ip, interface, vrf""",
                    (device,),
                )
            ]
        return {
            "scan": dict(scan_row) if scan_row else None,
            "macs": macs,
            "arps": arps,
        }

    def device_arp_rows(self, device: str) -> dict[str, object]:
        """Load one device's persisted scan and normalized ARP observations."""
        with self.connect() as db:
            scan_row = db.execute(
                "SELECT * FROM mac_scans WHERE device_name = ?", (device,)
            ).fetchone()
            arps = [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM arp_observations WHERE device_name = ?
                       ORDER BY ip, mac, interface, vrf""",
                    (device,),
                )
            ]
        return {
            "scan": dict(scan_row) if scan_row else None,
            "arps": arps,
        }

MacIndex = ObservationRepository
