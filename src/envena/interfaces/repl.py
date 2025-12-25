from src.envena.config import ROOT_LOGGER_NAME
import logging
import subprocess
import readline
import sqlite3
from pathlib import Path



# Initilazing
logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.REPL')

logger.info('Looking for awailable workspaces...')


if WORKSPACES != []:
    logger.info(f'Found workspaces: {','.join(WORKSPACES)}')
else:
    logger.info('No workspaces found')

print(WORKSPACES)
while True:
    pass