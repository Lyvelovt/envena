import logging
from src.envena.config import ROOT_LOGGER_NAME
from src.envena.base.arguments import Arguments, public_args



class Tool:
    __slots__ = ('VERSION', 'tool_func', 'logger', 'args')
    
    def __init__(self, tool_func, VERSION: float, args: Arguments = None):
        self.tool_func = None
        
        if not callable(tool_func):
            raise TypeError('send function must be callable')
        else:
            self.tool_func = tool_func

        if isinstance(args, Arguments) or args == None:
            self.args = args
        else:
            raise TypeError('invalid arguments got')
        
        if isinstance(VERSION, float):
            self.VERSION = VERSION
        else:
            raise TypeError('invalid tool version got')
        
    def start_tool(self):
        self.logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.{__class__.__name__}/{self.args.iface if not self.args == None else public_args.iface}')
        self.logger.info(f'***Script started, version: {self.VERSION}')
        self.tool_func(param=self.args if self.args else public_args, logger=self.logger)
