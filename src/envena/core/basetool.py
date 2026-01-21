import logging

from src.envena.core.arguments import Arguments, public_args
from src.envena.core.logger import ROOT_LOGGER_NAME
from src.envena.core.workspace import Workspaces


class BaseTool:
    __slots__ = ("VERSION", "tool_func", "logger", "args", "ws")

    def __init__(
        self, tool_func, VERSION: float, args: Arguments = None, ws: Workspaces = None
    ):
        self.tool_func = None
        self.ws = None

        if not callable(tool_func):
            raise TypeError("Send function must be callable")
        else:
            self.tool_func = tool_func

        if isinstance(args, Arguments) or args == None:
            self.args = args
        else:
            raise TypeError("Invalid arguments got")

        if isinstance(VERSION, float):
            self.VERSION = VERSION
        else:
            raise TypeError("Invalid tool version got")

    def start_tool(self):
        self.logger = logging.getLogger(
            f"{ROOT_LOGGER_NAME}.{self.__class__.__name__}.{self.tool_func.__name__}@{self.args.iface if self.args != None else public_args.iface}"
        )
        self.logger.info(f"# Script started, version: {self.VERSION}")
        try:
            self.tool_func(
                param=self.args if self.args else public_args,
                logger=self.logger,
                ws=self.ws,
            )
        except KeyboardInterrupt:
            self.logger.info("Aborted")
