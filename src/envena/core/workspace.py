import re
import sqlite3
from functools import wraps
from pathlib import Path
from typing import List, Optional

from src.envena.core.config import BASE_WORKSPACES_PATH


class Workspaces:
    def __init__(self, base_path: str = BASE_WORKSPACES_PATH):
        self.path = Path(base_path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._current_name: Optional[str] = None
        self.conn: Optional[sqlite3.Connection] = None

    def ensure_connection(func):
        """Decorator to prevent operations without an active database connection."""

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.conn:
                raise RuntimeError("No active workspace. Set 'current' property first")
            return func(self, *args, **kwargs)

        return wrapper

    @property
    def list(self) -> List[str]:
        """Scans directory for valid .db files."""
        return [f.stem for f in self.path.glob("*.db")]

    @property
    def current(self) -> Optional[str]:
        return self._current_name

    @current.setter
    def current(self, name: str):
        """Safely switches the active database connection."""
        if not self.is_workspace(name):
            raise ValueError(f"Workspace '{name}' does not exist")

        if self.conn:
            self.conn.close()

        self._current_name = name
        db_path = self.get_full_path(name)

        # check_same_thread=False allows multi-threaded use (e.g. with web frameworks)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        with self.conn:
            self.conn.execute("PRAGMA foreign_keys = ON;")
            self.conn.execute(
                "PRAGMA journal_mode = WAL;"
            )  # High-performance concurrent mode
            self.conn.execute(
                "PRAGMA busy_timeout = 5000;"
            )  # Wait up to 5s if DB is locked

    def is_workspace(self, name: str) -> bool:
        return self.get_full_path(name).exists()

    def get_full_path(self, name: str) -> Path:
        """Sanitizes filename to prevent Directory Traversal attacks."""
        clean_name = re.sub(r"[^\w\-_]", "", name)
        return self.path / f"{clean_name}.db"

    def create(self, name: str):
        """Initializes a new database with strict schema constraints."""
        db_path = self.get_full_path(name)
        if db_path.exists():
            raise FileExistsError(f"Workspace '{name}' already exists")

        with sqlite3.connect(str(db_path)) as temp_conn:
            schema = [
                "PRAGMA foreign_keys = ON;",
                """CREATE TABLE hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT UNIQUE NOT NULL,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    type TEXT DEFAULT 'Unknown',
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""",
                """CREATE TABLE wifi_aps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    bssid TEXT UNIQUE NOT NULL,
                    ssid TEXT,
                    channel INTEGER,
                    signal_dbm INTEGER,
                    encryption TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                )""",
                """CREATE TABLE wifi_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER UNIQUE NOT NULL, -- Prevents duplicate client entries
                    ap_id INTEGER,
                    signal_dbm INTEGER,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                    FOREIGN KEY (ap_id) REFERENCES wifi_aps (id) ON DELETE SET NULL
                )""",
                """CREATE TABLE services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    name TEXT,
                    version TEXT,
                    UNIQUE(host_id, port),
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                )""",
                """CREATE TABLE vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT,
                    UNIQUE(service_id, title), -- Prevents duplicate vulnerability reports
                    FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE
                )""",
            ]
            for cmd in schema:
                temp_conn.execute(cmd)
        return True

    def delete(self, name: str):
        """Closes connection and removes the database file."""
        db_path = self.get_full_path(name)
        if not db_path.exists():
            return False

        if self._current_name == name:
            if self.conn:
                self.conn.close()
                self.conn = None
            self._current_name = None

        db_path.unlink()
        return True

    @ensure_connection
    def set_host(
        self,
        mac: str,
        ip: str = None,
        hostname: str = None,
        vendor: str = None,
        htype: str = "Unknown",
    ):
        """Upsert host data. Normalizes MAC and updates existing records."""
        sql = """INSERT INTO hosts (mac, ip, hostname, vendor, type) 
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(mac) DO UPDATE SET 
                    ip = COALESCE(excluded.ip, ip),
                    hostname = COALESCE(excluded.hostname, hostname),
                    vendor = COALESCE(excluded.vendor, vendor),
                    type = CASE WHEN excluded.type != 'Unknown' THEN excluded.type ELSE type END,
                    last_seen = CURRENT_TIMESTAMP"""

        mac_clean = mac.lower().strip()
        with self.conn:  # Implicit transaction commit/rollback
            self.conn.execute(sql, (mac_clean, ip, hostname, vendor, htype))
            return self.get_host_id(mac=mac_clean)

    @ensure_connection
    def get_host_id(self, mac: str = None, ip: str = None) -> Optional[int]:
        """Finds host ID, prioritizing MAC over IP. Returns newest record if IP is duplicated."""
        if mac:
            res = self.conn.execute(
                "SELECT id FROM hosts WHERE mac = ?", (mac.lower().strip(),)
            ).fetchone()
            if res:
                return res[0]

        if ip:
            res = self.conn.execute(
                "SELECT id FROM hosts WHERE ip = ? ORDER BY last_seen DESC", (ip,)
            ).fetchone()
            if res:
                return res[0]

        return None

    @ensure_connection
    def set_wifi_ap(self, bssid: str, ssid: str, ch: int, sig: int, enc: str):
        """Upsert Access Point data and links to host record."""
        h_id = self.set_host(mac=bssid, hostname=ssid, htype="AP")
        sql = """INSERT INTO wifi_aps (host_id, bssid, ssid, channel, signal_dbm, encryption) 
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(bssid) DO UPDATE SET 
                    ssid=excluded.ssid, channel=excluded.channel, 
                    signal_dbm=excluded.signal_dbm, encryption=excluded.encryption"""
        with self.conn:
            self.conn.execute(sql, (h_id, bssid.lower().strip(), ssid, ch, sig, enc))
        return h_id

    @ensure_connection
    def set_service(self, host_id: int, port: int, name: str = None, ver: str = None):
        """Upsert service/port information for a specific host."""
        sql = """INSERT INTO services (host_id, port, name, version) VALUES (?, ?, ?, ?)
                 ON CONFLICT(host_id, port) DO UPDATE SET name=excluded.name, version=excluded.version"""
        with self.conn:
            self.conn.execute(sql, (host_id, port, name, ver))
            res = self.conn.execute(
                "SELECT id FROM services WHERE host_id=? AND port=?", (host_id, port)
            ).fetchone()
            return res[0]
