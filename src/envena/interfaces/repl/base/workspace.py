import sqlite3
from pathlib import Path

class Workspaces:
    def __init__(self, base_path: str = 'database/workspaces'):
        self.path = Path(base_path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._current = None  # Внутренняя переменная для хранения текущего воркспейса

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
            raise FileExistsError(f"Workspace '{name}' already exists.")
        
        # Создаем файл через sqlite3 (это сразу инициализирует БД)
        with sqlite3.connect(str(db_path)) as conn:
            conn.executescript('''
            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                mac_address TEXT,
                ip_address TEXT,
                vendor TEXT,
                connection_type TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS wifi_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                ssid TEXT,
                bssid TEXT,
                signal_strength INTEGER,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );
        ''') 
        return True

    def __repr__(self):
        return f"<Workspaces(current={self.current}, total={len(self.list)})>"