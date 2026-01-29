import argparse
import importlib
import logging
import pkgutil
import re
import sqlite3
from pathlib import Path

import cmd2
from rich.box import Box
from rich.console import Console
from rich.table import Table

import src.envena.modules.dot11 as dot11_tools
import src.envena.modules.ethernet as ethernet_tools
from src.envena.core.arguments import Arguments
from src.envena.core.config import ENVENA_VERSION
from src.envena.core.logger import ROOT_LOGGER_NAME

# from src.envena.interfaces.repl.repl_config import WORKSPACES, WORKSPACES_PATH, CURRENT_WORKSPACE, update_workspaces
from src.envena.core.workspace import Workspaces
from src.envena.ui.banner import envena_art


class EnvenaREPL(cmd2.Cmd):
    def __init__(self):
        super().__init__()
        self.args_obj = Arguments()
        self.logger = logging.getLogger(f"{ROOT_LOGGER_NAME}.{__class__.__name__}")
        self.tools = self._load_module_tools()
        self.console = Console()
        self.workspaces = Workspaces()
        self._int_args = ["count", "xid"]
        self._float_args = ["timeout"]
        self.aliases["q"] = "exit"
        self.aliases["quit"] = "exit"
        # self.update_promt()
        self.prompt = f"[{self.args_obj.iface}] [{self.workspaces.current}] >> "

    def update_prompt(self):
        iface = self.args_obj.iface
        ws = self.workspaces.current
        self.prompt = f"[{iface}] [{ws}] >> "

    def postcmd(self, stop, line):
        self.update_prompt()
        return stop

    intro = "\n".join(envena_art)

    ##############################
    # Import all available tools #
    ##############################

    PACKAGES = ["src.envena.modules.ethernet", "src.envena.modules.dot11"]

    def _load_module_tools(self):
        loaded_objects = {}
        base_packages = ["src.envena.modules.ethernet", "src.envena.modules.dot11"]

        for base_pkg_name in base_packages:
            try:
                base_pkg = importlib.import_module(base_pkg_name)
            except ImportError as e:
                self.logger.warning(f"Could not find base package {base_pkg_name}: {e}")
                continue

            for loader, module_name, is_pkg in pkgutil.walk_packages(
                base_pkg.__path__, base_pkg_name + "."
            ):
                if is_pkg:
                    continue

                try:
                    module = importlib.import_module(module_name)

                    parent_package_name = ".".join(module_name.split(".")[:-1])
                    parent_package = importlib.import_module(parent_package_name)
                    category = getattr(parent_package, "CATEGORY_DOC", "Misc")

                    short_name = module_name.split(".")[-1]
                    target_obj_name = f"t_{short_name}"

                    if hasattr(module, target_obj_name):
                        obj_class = getattr(module, target_obj_name)
                        tool_instance = obj_class()
                        tool_instance.category = category

                        self._create_command(short_name, tool_instance)

                        loaded_objects[short_name] = obj_class
                        self.logger.debug(
                            f'Imported "{target_obj_name}" (Category: {category})'
                        )

                except Exception as e:
                    self.logger.warning(f"Failed to load module {module_name}: {e}")

        return loaded_objects

    def _create_command(self, name, instance):
        @cmd2.with_category(instance.category)
        def command_wrapper(repl_self, arg):
            instance.ws = repl_self.workspaces
            instance.args = repl_self.args_obj
            instance.start_tool()

        command_wrapper.__doc__ = instance.__doc__
        setattr(self.__class__, f"do_{name}", command_wrapper)

    #################
    # COMMANDS PART #
    #################

    # workspace ======================================================== #
    workspace_parser = argparse.ArgumentParser(
        prog="workspace", description="manage workspaces"
    )
    workspace_subparsers = workspace_parser.add_subparsers(
        dest="action", help="action to perform"
    )
    workspace_subparsers.required = True

    # list
    workspace_subparsers.add_parser("list", help="show available workspaces")

    set_p = workspace_subparsers.add_parser("set", help="setting current workspace")
    set_p.add_argument("name", type=str, help="name of workspace")

    # create
    create_p = workspace_subparsers.add_parser("create", help="creating new workspace")
    create_p.add_argument("name", type=str)

    # delete
    delete_p = workspace_subparsers.add_parser("delete", help="delete workspace")
    delete_p.add_argument("name", type=str)

    @cmd2.with_argparser(workspace_parser)
    @cmd2.with_category("Management")
    def do_workspace(self, args):
        if args.action == "list":
            output_table = Table(
                title="Available workspaces",
                header_style="bold magenta",
                border_style="yellow",
            )

            output_table.add_column("#", justify="right", style="cyan", no_wrap=True)
            output_table.add_column("Name", style="green")
            output_table.add_column("Status", justify="center")

            for i, ws in enumerate(self.workspaces.list, 1):
                status = (
                    "[bold green]Active[/bold green]"
                    if self.workspaces.current == ws
                    else "[white]Idle[/white]"
                )
                output_table.add_row(str(i), ws, status)
            #
            # self.poutput(output_table)
            self.console.print(output_table)

        elif args.action == "create":
            # db_file = self.workspaces.path / Path(args.name)
            try:
                self.workspaces.create(args.name)
                self.poutput(f"created new workspace: '{args.name}'")
            except Exception as e:
                self.perror(
                    f"error: cannot create workspace with name '{args.name}': {e}"
                )

        elif args.action == "delete":
            if input(
                f'are you absolutely sure that you want to permanently delete "{args.name}"? (y/N): '
            ).lower() in ["y", "yes", "yeah", "yep", "yeap", "yea"]:
                self.workspaces.delete(args.name)
                self.poutput(f"deleted: {args.name}")
            else:
                self.poutput("interrupted")

        elif args.action == "set":
            self.workspaces.current = args.name
            # self.poutput(f'{str(WORKSPACES_PATH)}/{args.name}.db')
            # self.conn = sqlite3.connect(self.workspaces.get_full_path(self.workspaces.current))
            # self.cursor = self.conn.cursor()
            self.poutput(f'set "{args.name}" workspace')

    # args ======================================================== #
    args_parser = argparse.ArgumentParser(prog="args", description="manage arguments")
    args_subparsers = args_parser.add_subparsers(
        dest="action", help="action to perform"
    )

    args_subparsers.add_parser("list", help="show all current arguments")

    args_subparsers.add_parser("default", help="reset all arguments to default values")

    get_p = args_subparsers.add_parser("get", help="show value of argument")
    get_p.add_argument("expression", nargs=argparse.REMAINDER, help="argument to show")

    set_p = args_subparsers.add_parser("set", help="set a value: args set key value")
    set_p.add_argument(
        "expression", nargs=argparse.REMAINDER, help="key value expression"
    )

    @cmd2.with_argparser(args_parser)
    @cmd2.with_category("Management")
    def do_args(self, ns: argparse.Namespace):
        if ns.action == "list":
            self._show_args()

        elif ns.action == "default":
            self.args_obj.default()
            self.poutput("all arguments to default")

        elif ns.action == "set":
            expr = ns.expression
            if len(expr) != 2:
                self.perror('error: excepted "key value" form')
                return

            key, val = (expr[0], expr[1])
            if key in self._int_args:  # ['count', 'xid']:
                try:
                    setattr(self.args_obj, key, int(val))
                except ValueError:
                    self.perror("error: excepted integer")
            elif key in self._float_args:  # ['timeout']:
                try:
                    setattr(self.args_obj, key, float(val))
                except ValueError:
                    self.perror("error: excepted integer or float")
            else:
                setattr(self.args_obj, key, val)

        elif ns.action == "get":
            if len(ns.expression) != 1:
                self.perror("error: excepted argument to show")
                return
            key = ns.expression[0]

            if key in self.args_obj.__slots__ and key != "logger":
                val = getattr(self.args_obj, key)
                self.poutput(f"{key} : {val}")
            else:
                self.perror(f'error: argument "{key}" is invalid')

    def _show_args(self):
        output_table = Table(
            title="[bold cyan]Workspace Arguments[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            min_width=60,
            expand=False,
        )

        output_table.add_column("Parameter", style="cyan", no_wrap=True)
        output_table.add_column("Value", justify="left")
        output_table.add_column("Category", style="italic dim")

        categories = {
            "Payload..(L7)": ["xid", "dns_server"],
            "TCP/UDP..(L4)": ["port_src", "port_dst"],
            "Network..(L3)": ["sub_ip", "sub_mask"],
            "IP.......(L3)": ["ip_src", "ip_dst"],
            "Ethernet.(L2)": ["eth_src", "eth_dst"],
            "Dot11....(L2)": ["hw_src", "hw_dst", "bssid", "ssid"],
            "Device...(L2)": ["iface"],
            "Sender..(App)": ["count", "timeout"],
            "Other...(App)": ["input"],
        }

        all_slotted = list(self.args_obj.__slots__)
        if "logger" in all_slotted:
            all_slotted.remove("logger")

        for category, params in categories.items():
            output_table.add_section()
            for p in params:
                if p in all_slotted:
                    val = getattr(self.args_obj, p)

                    display_val = f"[bold green]{val}[/bold green]"

                    output_table.add_row(p, display_val, category)
                    all_slotted.remove(p)

        # for p in all_slotted:
        #     val = getattr(self.args_obj, p)
        #     display_val = f"[bold green]{val}[/bold green]" if val is not NOT_SET else "[dim]None[/dim]"
        #     output_table.add_row(p, display_val, "Misc")

        self.console.print(output_table)
        # self.poutput(output_table)

    def do_exit(self, _: argparse.Namespace):
        """Exit from REPL"""
        return True
        if input("You sure you want to exit? (y/N): ").lower() in [
            "y",
            "yeap",
            "yea",
            "yes",
            "yeah",
            "fuck you stupid clanker let me out",
            ":q!",
        ]:
            return True
        return False
