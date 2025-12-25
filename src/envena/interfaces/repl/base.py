import sqlite3
import argparse
import cmd2
from src.envena.banner import envena_art
from pathlib import Path
import logging
from src.envena.config import ROOT_LOGGER_NAME
import re
from rich import table, console
from src.envena.base.arguments import Arguments

import pkgutil
import importlib

import src.modules.ethernet.tools as ethernet_tools
import src.modules.dot11.tools as dot11_tools

Path('database/workspaces').mkdir(exist_ok=True, parents=True)
WORKSPACES = list(Path('database/workspaces/').iterdir())
CURRENT_WORKSPACE = None

class EnvenaREPL(cmd2.Cmd):
    def __init__(self):
        self.args = Arguments()
        self.logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.{__class__.__name__}')
        self.tools = self._load_module_tools()
    
    intro = '\n'.join(envena_art)
    prompt = "3NV3N4=> "
    
    
    ##############################
    # Import all available tools #
    ##############################

    PACKAGES = [
        'src.modules.ethernet.tools',
        'src.modules.dot11.tools'
    ]

    def _load_module_tools(self):
        loaded_objects = {}

        for package_name in self.PACKAGES:
            try:
                package = importlib.import_module(package_name)
            except ImportError as e:
                print(f"[!] Ошибка: Пакет {package_name} не найден: {e}")
                self.logger.error(f'Failed to locate "{package_name}" packet')
                continue

            for loader, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
                if is_pkg: continue
                
                full_module_path = f"{package_name}.{module_name}"
                
                try:
                    module = importlib.import_module(full_module_path)
                    
                    target_obj_name = f"t_{module_name}"
                    if hasattr(module, target_obj_name):
                        obj = getattr(module, target_obj_name)
                        loaded_objects[module_name] = obj
                        self.logger.debug(f'Succesfully import "{target_obj_name}" from "{module_name}"')
                    else:
                        self.logger.error(f'Failed to locate "{target_obj_name}" in "{module_name}"')
                        
                except Exception as e:
                    self.logger.error(f'Failed to import "{full_module_path}": {e}')

        return loaded_objects

    

    
    ###########################
    # Args validate functions #
    ###########################
    
    def is_workspace(value)->bool:
        if not value in WORKSPACES:
            raise argparse.ArgumentTypeError(f'{value} is not workspace. Try: "workspace create {value}"')
        else:
            return value
    
    def validate_filename(filename):
        forbidden_chars = r'[\\/:*?"<>|]'
        if re.search(forbidden_chars, filename):
            raise argparse.ArgumentTypeError(f"File name has banned symbols: {filename}")
        
        reserved = ["CON", "PRN", "AUX", "NUL"]
        if filename.split('.')[0].upper() in reserved:
            raise argparse.ArgumentTypeError(f"Name '{filename}' reserved by system")
            
        return filename
    
    
    #################
    # COMMANDS PART #
    #################
    
    # workspace ======================================================== #
    workspace_parser = argparse.ArgumentParser()
    workspace_subparsers = workspace_parser.add_subparsers(dest='action', help='Available actions')
    workspace_subparsers.required = True
    
    # list
    workspace_subparsers.add_parser('list', help='Print available workspaces')

    set_p = workspace_subparsers.add_parser('set', help='Setting workspace')
    set_p.add_argument('name', type=is_workspace, help='Name of workspace') 

    # create
    create_p = workspace_subparsers.add_parser('create', help='Creating new workspace')
    create_p.add_argument('name', type=validate_filename)
    
    # delete
    delete_p = workspace_subparsers.add_parser('delete', help='Delete workspace')
    delete_p.add_argument('name', type=is_workspace)

    @cmd2.with_argparser(workspace_parser)
    def do_workspace(self, args):
        if args.action == 'list':
            output_table = table(
            title="Available workspaces", 
            header_style="bold magenta", 
            border_style="yellow"
        )

            output_table.add_column("#", justify="right", style="cyan", no_wrap=True)
            output_table.add_column("Name", style="green")
            output_table.add_column("Status", justify="center")

            for i, ws in enumerate(self.WORKSPACES, 1):
                status = "[bold green]Active[/bold green]" if CURRENT_WORKSPACE == i else "[white]Idle[/white]"
                output_table.add_row(str(i), ws, status)

                console.print(output_table)
        
        elif args.action == 'create':
            Path(f"workspaces/{args.name}.db").mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(f'{args.name}.db')
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
            conn.close()
            self.poutput(f'created new workspace: {args.name}')
        
        elif args.action == 'delete':
            if input(f'are you absolutely sure that you want to permanently delete "{args.name}"? (y/N): ').lower() in \
                ['y', 'yes', 'yeah', 'yep', 'yeap', 'yea']:
                    Path(f'database/workspaces/{args.name}').unlink(missing_ok=1)
                    self.poutput(f'deleted: {args.name}')
            else:
                self.poutput('interrupted')
        
        elif args.action == 'set':
            self.conn = sqlite3.connect(f'database/workspace/{args.name}')
            self.cursor = self.conn.cursor()
            
            
    ################
    # MODULES PART #
    ################
    
    
a = EnvenaREPL()