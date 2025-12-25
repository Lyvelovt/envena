import sqlite3
import argparse
import cmd2
from src.envena.banner import envena_art
from pathlib import Path
import logging
from src.envena.config import ROOT_LOGGER_NAME
import re


Path('database/workspaces').mkdir(exist_ok=True, parents=True)
WORKSPACES = list(Path('database/workspaces/').iterdir())

class EnvenaREPL(cmd2.Cmd):
    def __init__(self):
        self.logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.{__class__.__name__}')
    
    intro = '\n'.join(envena_art)
    prompt = "3NV3N4=> "
    
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
            raise argparse.ArgumentTypeError(f"Имя файла содержит запрещенные символы: {filename}")
        
        # Проверка на зарезервированные имена
        reserved = ["CON", "PRN", "AUX", "NUL"]
        if filename.split('.')[0].upper() in reserved:
            raise argparse.ArgumentTypeError(f"Имя '{filename}' зарезервировано системой")
            
        return filename
    
    # Создаем парсер для аргументов конкретной команды
    workspace_parser = argparse.ArgumentParser()
    workspace_parser.add_argument('list', help="Print awailable workspaces")
    workspace_parser.add_argument('set', type=is_workspace, default=None, help="Setting workspace")
    

    

    @cmd2.with_argparser(workspace_parser)
    def do_workspace(self, args):
        """Команда say выводит текст несколько раз"""
        for _ in range(args.repeat):
            self.poutput(args.text)

commands = {
    'workspace
}