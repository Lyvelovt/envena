from pathlib import Path
import argparse
from typing import List

WORKSPACES_PATH = Path('database/workspaces')
WORKSPACES_PATH.mkdir(exist_ok=True, parents=True)

class Workspaces():
    def update_workspaces(self):
        self.list = []
        for ws in list(WORKSPACES_PATH.iterdir()):
            enum_ws = str(ws)
            enum_ws = enum_ws.split('/')
            enum_ws = enum_ws[len(enum_ws)-1]
            self.list.append(enum_ws[:len(enum_ws)-3])

    def _is_workspace(self, value)->bool:
        if not value in self.list:
            return False
            # 
        else:
            return True
    
    def __init__(self):
        self.update_workspaces()
        self.list: List[str]
        self.path: Path = WORKSPACES_PATH
        self.path.mkdir(parents=True, exist_ok=True)
        self.current: str = None
    
        
    def __getattribute__(self, name):
        if name == 'list':
            self.update_workspaces()
            return self.list
    
    def __setattr__(self, name, value):
        if name == 'current':
            if not self._is_workspace(value):
                raise argparse.ArgumentTypeError(f'{value} is not workspace. Try: "workspace create {value}"')
            else:
                object.__setattr__(self, 'current', value)
    
    def get_name(self):
        return str(self.name)
    