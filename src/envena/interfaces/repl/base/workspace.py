import sqlite3
from pathlib import Path

class Workspaces:
    def __init__(self, base_path: str = 'database/workspaces'):
        self.path = Path(base_path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._current = None
        self.conn = None

    @property
    def list(self):
        """Возвращает список имен воркспейсов (без .db), сканируя папку."""
        return [f.stem for f in self.path.glob("*.db")]

    @property
    def current(self):
        return self._current

    @current.setter
    def current(self, value):
        if value not in self.list:
            raise ValueError(f'"{value}" is not a workspace. Use "workspace create {value}" first.')
        self._current = value
        if self.conn:
            self.conn.close()
        self.conn = sqlite3.connect(self.get_full_path(self.current), check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.conn.execute("PRAGMA journal_mode = WAL;")

    def is_workspace(self, name: str) -> bool:
        """Проверяет существование воркспейса."""
        return name in self.list

    def get_full_path(self, name: str) -> Path:
        """Возвращает полный путь к файлу .db."""
        return self.path / f"{name}.db"

    def create(self, name: str):
        """Создает новый файл базы данных с таблицами hosts, wifi и services."""
        db_path = self.get_full_path(name)
        if db_path.exists():
            raise FileExistsError(f'workspace "{name}" already exists')
        
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON;")

            # Главная таблица хостов
            cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                type TEXT DEFAULT 'Unknown',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

            # Точки доступа
            cursor.execute('''CREATE TABLE IF NOT EXISTS wifi_aps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ssid TEXT,
                bssid TEXT UNIQUE,
                channel INTEGER,
                signal_dbm INTEGER,
                encryption TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
            )''')

            # Wi-Fi клиенты
            cursor.execute('''CREATE TABLE IF NOT EXISTS wifi_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ap_id INTEGER,
                signal_dbm INTEGER,
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                FOREIGN KEY (ap_id) REFERENCES wifi_aps (id) ON DELETE SET NULL
            )''')

            # Сервисы (порты)
            cursor.execute('''CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER,
                name TEXT,
                version TEXT,
                UNIQUE(host_id, port),
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
            )''')

            # Уязвимости
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER,
                title TEXT,
                url TEXT,
                FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE
            )''')
            conn.commit()
        return True

    def delete(self, name: str):
        """Удаляет файл воркспейса."""
        db_path = self.get_full_path(name)
        if db_path.exists():
            db_path.unlink()
            if self._current == name:
                self._current = None
                if self.conn:
                    self.conn.close()
                    self.conn = None
            return True
        else:
            raise FileExistsError(f'workspace "{name}" not exists')

    def __repr__(self):
        return f"<Workspaces(current={self.current}, total={len(self.list)})>"

    # --- API МЕТОДЫ ---

    def set_host(self, mac: str, ip: str = None, hostname: str = None, vendor: str = None, htype: str = 'Unknown'):
        if not self.conn:
            return False
        """Запись хоста. Обновляет данные, если MAC уже существует."""
        sql = '''INSERT INTO hosts (mac, ip, hostname, vendor, type) 
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(mac) DO UPDATE SET 
                    ip = COALESCE(excluded.ip, ip),
                    hostname = COALESCE(excluded.hostname, hostname),
                    vendor = COALESCE(excluded.vendor, vendor),
                    type = COALESCE(excluded.type, type),
                    last_seen = CURRENT_TIMESTAMP'''
        self.conn.execute(sql, (mac.lower(), ip, hostname, vendor, htype))
        self.conn.commit()
        return self.conn.execute("SELECT id FROM hosts WHERE mac=?", (mac.lower(),)).fetchone()[0]

    def set_wifi_ap(self, bssid: str, ssid: str, ch: int, sig: int, enc: str):
        """Запись AP."""
        h_id = self.set_host(mac=bssid, hostname=ssid, htype='AP')
        sql = '''INSERT INTO wifi_aps (host_id, bssid, ssid, channel, signal_dbm, encryption) 
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(bssid) DO UPDATE SET 
                    ssid=excluded.ssid, channel=excluded.channel, 
                    signal_dbm=excluded.signal_dbm, encryption=excluded.encryption'''
        self.conn.execute(sql, (h_id, bssid.lower(), ssid, ch, sig, enc))
        self.conn.commit()
        return h_id

    def set_wifi_client(self, mac: str, ap_bssid: str = None, sig: int = None):
        """Запись клиента Wi-Fi."""
        h_id = self.set_host(mac=mac, htype='Client')
        ap_id = None
        if ap_bssid:
            res = self.conn.execute("SELECT id FROM wifi_aps WHERE bssid=?", (ap_bssid.lower(),)).fetchone()
            if res: ap_id = res[0]
        self.conn.execute("INSERT INTO wifi_clients (host_id, ap_id, signal_dbm) VALUES (?, ?, ?)", (h_id, ap_id, sig))
        self.conn.commit()

    def set_service(self, host_id: int, port: int, name: str = None, ver: str = None):
        """Запись сервиса."""
        sql = '''INSERT INTO services (host_id, port, name, version) VALUES (?, ?, ?, ?)
                 ON CONFLICT(host_id, port) DO UPDATE SET name=excluded.name, version=excluded.version'''
        self.conn.execute(sql, (host_id, port, name, ver))
        self.conn.commit()
        return self.conn.execute("SELECT id FROM services WHERE host_id=? AND port=?", (host_id, port)).fetchone()[0]

    def set_vuln(self, service_id: int, title: str, url: str = None):
        self.conn.execute('INSERT INTO vulns (service_id, title, url) VALUES (?, ?, ?)', (service_id, title, url))
        self.conn.commit()
    
    def get_host_id(self, mac: str = None, ip: str = None):
        """
        Возвращает host_id. 
        Поиск приоритетно по MAC, затем по IP.
        """
        # self._check_connection()
        
        # 1. Сначала ищем по MAC
        if mac:
            res = self.conn.execute("SELECT id FROM hosts WHERE mac = ?", (mac.lower(),)).fetchone()
            if res:
                return res[0]
        
        # 2. Если по MAC не нашли или его не дали, ищем по IP
        if ip:
            res = self.conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
            if res:
                return res[0]
        
        return None