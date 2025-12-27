import sqlite3
from pathlib import Path

class Workspaces:
    def __init__(self, base_path: str = 'database/workspaces'):
        self.path = Path(base_path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._current = None  # Внутренняя переменная для хранения текущего воркспейса
        self.conn = None

    @property
    def list(self):
        """Возвращает список имен воркспейсов (без .db), сканируя папку."""
        # .stem возвращает имя файла без расширения
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
        self.conn = sqlite3.connect(self.get_full_path(self.current))

    def is_workspace(self, name: str) -> bool:
        """Проверяет существование воркспейса."""
        return name in self.list

    def get_full_path(self, name: str) -> Path:
        """Возвращает полный путь к файлу .db."""
        return self.path / f"{name}.db"

    def create(self, name: str):
        """Создает новый файл базы данных, если его нет."""
        db_path = self.get_full_path(name)
        if db_path.exists():
            raise FileExistsError(f'workspace "{name}" already exists')
        # Создаем файл через sqlite3 (это сразу инициализирует БД)
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            # Включаем поддержку Foreign Keys (обязательно для SQLite)
            cursor.execute("PRAGMA foreign_keys = ON;")

            # Базовая таблица устройств
            cursor.execute('''CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE,
                vendor TEXT,
                seen_count INTEGER DEFAULT 1
            )''')

            # Данные сканирования Wi-Fi
            cursor.execute('''CREATE TABLE IF NOT EXISTS wifi_data (
                bssid TEXT PRIMARY KEY,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                FOREIGN KEY (bssid) REFERENCES targets (mac)
            )''')

            # Данные сканирования IP/Nmap
            cursor.execute('''CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_mac TEXT,
                ip TEXT,
                port INTEGER,
                product TEXT,
                version TEXT,
                FOREIGN KEY (target_mac) REFERENCES targets (mac)
            )''')

            # Уязвимости
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER,
                title TEXT,
                url TEXT,
                FOREIGN KEY (service_id) REFERENCES services (id)
            )''')
            conn.commit()
        return True

    def delete(self, name: str):
        """Удаляет файл воркспейса."""
        db_path = self.get_full_path(name)
        if db_path.exists():
            db_path.unlink()
            # Если удалили текущий воркспейс, сбрасываем _current
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
    
    def set_target(self, mac: str, vendor: str = None):
        """Базовая запись устройства (L2)."""
        sql = '''INSERT INTO targets (mac, vendor) VALUES (?, ?)
                 ON CONFLICT(mac) DO UPDATE SET 
                 seen_count = seen_count + 1,
                 vendor = COALESCE(excluded.vendor, vendor)'''
        self.conn.execute(sql, (mac, vendor))
        self.conn.commit()

    def set_wifi(self, bssid: str, ssid: str, channel: int, enc: str):
        """Запись Wi-Fi сети. Сначала создает таргет, если его нет."""
        self.save_target(bssid)
        sql = '''INSERT OR REPLACE INTO wifi_data (bssid, ssid, channel, encryption)
                 VALUES (?, ?, ?, ?)'''
        self.conn.execute(sql, (bssid, ssid, channel, enc))
        self.conn.commit()

    def set_service(self, mac: str, ip: str, port: int, prod: str = None, ver: str = None):
        """Запись найденного порта/сервиса."""
        self.save_target(mac)
        sql = '''INSERT INTO services (target_mac, ip, port, product, version)
                 VALUES (?, ?, ?, ?, ?)'''
        self.conn.execute(sql, (mac, ip, port, prod, ver))
        self.conn.commit()
        # Возвращаем ID созданного сервиса, чтобы привязать к нему уязвимости
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def set_vuln(self, service_id: int, title: str, url: str = None):
        """Запись уязвимости для конкретного сервиса."""
        sql = 'INSERT INTO vulns (service_id, title, url) VALUES (?, ?, ?)'
        self.conn.execute(sql, (service_id, title, url))
        self.conn.commit()
    
    def get_summary(self):
        """Возвращает полную картину: IP, MAC, Вендор и кол-во портов."""
        sql = '''
            SELECT t.mac, s.ip, t.vendor, COUNT(s.port) as port_count
            FROM targets t
            LEFT JOIN services s ON t.mac = s.target_mac
            GROUP BY t.mac
        '''
        return self.conn.execute(sql).fetchall()

    def get_host_services(self, mac: str):
        """Список всех портов для конкретного MAC."""
        sql = 'SELECT port, product, version FROM services WHERE target_mac = ?'
        return self.conn.execute(sql, (mac,)).fetchall()

    def get_vuln(self):
        """Список всех найденных уязвимостей с привязкой к IP и порту."""
        sql = '''
            SELECT s.ip, s.port, v.title, v.url
            FROM vulns v
            JOIN services s ON v.service_id = s.id
        '''
        return self.conn.execute(sql).fetchall()