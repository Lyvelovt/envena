import sqlite3
import argparse
import cmd2
from src.envena.ui.banner import envena_art
from pathlib import Path
import logging
from src.envena.core.logger import ROOT_LOGGER_NAME
import re
from rich.table import Table
from rich.console import Console
from rich.box import Box
from src.envena.core.arguments import Arguments

from src.envena.core.config import ENVENA_VERSION

import pkgutil
import importlib

import src.envena.modules.ethernet as ethernet_tools
import src.envena.modules.dot11 as dot11_tools


# from src.envena.interfaces.repl.repl_config import WORKSPACES, WORKSPACES_PATH, CURRENT_WORKSPACE, update_workspaces
from src.envena.core.workspace import Workspaces

class EnvenaREPL(cmd2.Cmd):
    def __init__(self):
        super().__init__()
        self.args_obj = Arguments()
        self.logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.{__class__.__name__}')
        self.tools = self._load_module_tools()
        self.console = Console()
        self.workspaces = Workspaces()
        self._int_args = ['count', 'xid']
        self._float_args = ['timeout']
        self.aliases['q'] = 'exit'
        self.aliases['quit'] = 'exit'
        
        self.prompt = f"ENVENA{ENVENA_VERSION}-{self.args_obj.iface}-[{self.workspaces.current}]-> "
    
    def update_prompt(self):
        iface = self.args_obj.iface
        ws = self.workspaces.current
        self.prompt = f"ENVENA{ENVENA_VERSION}-{iface}-[{ws}]-> "

    def postcmd(self, stop, line):
        self.update_prompt()
        return stop
    
    
    intro = '\n'.join(envena_art)
    
    ##############################
    # Import all available tools #
    ##############################

    PACKAGES = [
        'src.envena.modules.ethernet',
        'src.envena.modules.dot11'
    ]

    def _load_module_tools(self):
        loaded_objects = {}

        for package_name in self.PACKAGES:
            try:
                package = importlib.import_module(package_name)
            except ImportError as e:
                self.logger.error(f'Failed to locate "{package_name}" packet: {e}')
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
                    raise e

        return loaded_objects

    

    ###########################
    # Args validate functions #
    ###########################
    
    
    
    def validate_filename(filename):
        forbidden_chars = r'[\\/:*?"<>|]'
        if re.search(forbidden_chars, filename):
            raise argparse.ArgumentTypeError(f"file name has banned symbols: {filename}")
        
        reserved = ["CON", "PRN", "AUX", "NUL"]
        if filename.split('.')[0].upper() in reserved:
            raise argparse.ArgumentTypeError(f"Name '{filename}' reserved by system")
            
        return filename
    
    
    #################
    # COMMANDS PART #
    #################
    
    # workspace ======================================================== #
    workspace_parser = argparse.ArgumentParser(prog='workspace', description='manage workspaces')
    workspace_subparsers = workspace_parser.add_subparsers(dest='action', help='action to perform')
    workspace_subparsers.required = True
    
    # list
    workspace_subparsers.add_parser('list', help='show available workspaces')

    set_p = workspace_subparsers.add_parser('set', help='setting current workspace')
    set_p.add_argument('name', type=str, help='name of workspace') 

    # create
    create_p = workspace_subparsers.add_parser('create', help='creating new workspace')
    create_p.add_argument('name', type=validate_filename)
    
    # delete
    delete_p = workspace_subparsers.add_parser('delete', help='delete workspace')
    delete_p.add_argument('name', type=str)

    @cmd2.with_argparser(workspace_parser)
    def do_workspace(self, args):
        if args.action == 'list':
            output_table = Table(
            title="Available workspaces", 
            header_style="bold magenta", 
            border_style="yellow"
        )

            output_table.add_column("#", justify="right", style="cyan", no_wrap=True)
            output_table.add_column("Name", style="green")
            output_table.add_column("Status", justify="center")
            
            
            for i, ws in enumerate(self.workspaces.list, 1):
                status = "[bold green]Active[/bold green]" if self.workspaces.current == ws else "[white]Idle[/white]"
                output_table.add_row(str(i), ws, status)
# 
                # self.poutput(output_table)
            self.console.print(output_table)
        
        elif args.action == 'create':
            # db_file = self.workspaces.path / Path(args.name)
            self.workspaces.create(args.name)
            self.poutput(f'created new workspace: {args.name}')
        
        elif args.action == 'delete':
            if input(f'are you absolutely sure that you want to permanently delete "{args.name}"? (y/N): ').lower() in \
                ['y', 'yes', 'yeah', 'yep', 'yeap', 'yea']:
                    self.workspaces.delete(args.name)
                    self.poutput(f'deleted: {args.name}')
            else:
                self.poutput('interrupted')
        
        elif args.action == 'set':
            self.workspaces.current = args.name
            # self.poutput(f'{str(WORKSPACES_PATH)}/{args.name}.db')
            # self.conn = sqlite3.connect(self.workspaces.get_full_path(self.workspaces.current))
            # self.cursor = self.conn.cursor()
            self.poutput(f'set "{args.name}" workspace')
            
    # args ======================================================== #
    args_parser = argparse.ArgumentParser(prog='args', description='manage arguments')
    args_subparsers = args_parser.add_subparsers(dest='action', help='action to perform')

    args_subparsers.add_parser('list', help='show all current arguments')

    args_subparsers.add_parser('default', help='reset all arguments to default values')

    get_p = args_subparsers.add_parser('get', help='show value of argument')
    get_p.add_argument('expression', nargs=argparse.REMAINDER, help='argument to show') 
    
    set_p = args_subparsers.add_parser('set', help='set a value: args set key value')
    set_p.add_argument('expression', nargs=argparse.REMAINDER, help='key value expression')
    
    

    @cmd2.with_argparser(args_parser)
    def do_args(self, ns: argparse.Namespace):        
        if ns.action == 'list':
            self._show_args()

        elif ns.action == 'default':
            self.args_obj.default()
            self.poutput("all arguments to default")

        elif ns.action == 'set':
            expr = ns.expression
            if len(expr) != 2:
                self.perror('error: excepted "key value" form')
                return
            
            key, val = (expr[0], expr[1])
            if key in self._int_args: #['count', 'xid']:
                try:
                    setattr(self.args_obj, key, int(val))
                except ValueError:
                    self.perror('error: excepted integer')
            elif key in self._float_args: # ['timeout']:
                try:
                    setattr(self.args_obj, key, float(val))
                except ValueError:
                    self.perror('error: excepted integer or float')
            else:
                setattr(self.args_obj, key, val)

        elif ns.action == 'get':
            if len(ns.expression) != 1:
                self.perror('error: excepted argument to show')
                return
            key = ns.expression[0]
            
            if key in self.args_obj.__slots__ and key != 'logger':
                val = getattr(self.args_obj, key)
                self.poutput(f'{key} : {val}')
            else:
                self.perror(f'error: argument "{key}" is invalid')
                    

    def _show_args(self):
        output_table = Table(
            title="[bold cyan]Workspace Arguments[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            min_width=60,
            expand=False
        )

        output_table.add_column("Parameter", style="cyan", no_wrap=True)
        output_table.add_column("Value", justify="left")
        output_table.add_column("Category", style="italic dim")

        categories = {
            "Payload..(L7)": ['xid', 'dns_server'],
            "TCP/UDP..(L4)": ['port_src', 'port_dst'],
            "Network..(L3)": ['sub_ip', 'sub_mask'],
            "IP.......(L3)": ['ip_src', 'ip_dst'],
            "Ethernet.(L2)": ['eth_src', 'eth_dst'],
            "Dot11....(L2)": ['hw_src', 'hw_dst', 'bssid', 'ssid'],
            "Device...(L2)": ['iface'],
            "Sender..(App)": ['count', 'timeout'],
            "Other...(App)": ['input']
        }

        all_slotted = list(self.args_obj.__slots__)
        if 'logger' in all_slotted: all_slotted.remove('logger')

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
        if input("You sure you want to exit? (y/N): ").lower() in\
            ['y', 'yeap', 'yea', 'yes', 'yeah', 'fuck you stupid clanker let me out', ':q!']:
            return True
        return False
    
    ################
    # MODULES PART #
    ################

    

# --- Category: Network Discovery ---

    @cmd2.with_category("Network Discovery")
    def do_arpscan(self, _: argparse.Namespace):
        """
        Scan the network using ARP protocol to discover live hosts.
        Target Specification (input):
          - Single IP: 192.168.1.1
          - Range: 192.168.1.1-100 or 192.168.1.1,192.168.1.2
          - CIDR: 192.168.1.0/24
        Output: IP, MAC, Hostname, and Vendor (saved to workspace).
        """
        if not self.tools.get('arpscan'):
            self.poutput('ARPscan module is unavailable!')
            return
        self.tools['arpscan'].ws = self.workspaces
        self.tools['arpscan'].args = self.args_obj
        self.tools['arpscan'].start_tool()

    @cmd2.with_category("Network Discovery")
    def do_icmpmap(self, _: argparse.Namespace):
        """
        Map live hosts and trace paths using ICMP echo requests.
        Usage: 
          - Scan range: set 'input' to '192.168.1.1-50'
          - Single target: set 'ip_dst' to '8.8.8.8'
        Features: Detects hop-by-hop path and measures response time.
        """
        if not self.tools.get('icmpmap'):
            self.poutput('ICMPmap module is unavailable!')
            return
        self.tools['icmpmap'].ws = self.workspaces
        self.tools['icmpmap'].args = self.args_obj
        self.tools['icmpmap'].start_tool()

    @cmd2.with_category("Network Discovery")
    def do_vulnscan(self, _: argparse.Namespace):
        """
        Perform deep vulnerability scanning using Nmap and Searchsploit.
        Target Specification (input): Single IP, Range, or CIDR.
        Output: Table with Host, Port, Service Version, and CVE/Exploit links.
        """
        if not self.tools.get('vulnscan'):
            self.poutput('VULNscan module is unavailable!')
            return
        self.tools['vulnscan'].ws = self.workspaces
        self.tools['vulnscan'].args = self.args_obj
        self.tools['vulnscan'].start_tool()

    # --- Category: Attacks & Exploitation ---

    @cmd2.with_category("Attacks & Exploitation")
    def do_camoverflow(self, _: argparse.Namespace):
        """
        Perform CAM table overflow attack (MAC flooding).
        Usage: Floods the switch with random source MAC addresses to force 'fail-open' mode.
        Parameters: Uses 'iface' and 'timeout' (delay between packets, default: 0.002).
        """
        if not self.tools.get('camoverflow'):
            self.poutput('CamOF module is unavailable!')
            return
        self.tools['camoverflow'].ws = self.workspaces
        self.tools['camoverflow'].args = self.args_obj
        self.tools['camoverflow'].start_tool()

    @cmd2.with_category("Attacks & Exploitation")
    def do_dhcp_starve(self, _: argparse.Namespace):
        """
        Exhaust DHCP server IP pool by sending massive DHCP Discover requests.
        Usage: Sends packets with random transaction IDs and source MACs.
        Parameters: Uses 'iface' and 'timeout' (default: 0.5s).
        """
        if not self.tools.get('dhcp_starve'):
            self.poutput('DHCPstarve module is unavailable!')
            return
        self.tools['dhcp_starve'].ws = self.workspaces
        self.tools['dhcp_starve'].args = self.args_obj
        self.tools['dhcp_starve'].start_tool()

    # --- Category: Sniffing & MITM ---

    @cmd2.with_category("Sniffing & MITM")
    def do_detect_mitm(self, _: argparse.Namespace):
        """
        Monitor network for ARP spoofing and Man-in-the-Middle attacks.
        Usage: Analyzes ARP traffic for MAC/IP conflicts and unusual TTL changes.
        Parameters: Set 'input' to Gateway IP for specific monitoring.
        Output: Saves captured suspicious traffic to .pcap file.
        """
        if not self.tools.get('detect_mitm'):
            self.poutput('DetectMITM module is unavailable!')
            return
        self.tools['detect_mitm'].ws = self.workspaces
        self.tools['detect_mitm'].args = self.args_obj
        self.tools['detect_mitm'].start_tool()

    @cmd2.with_category("Sniffing & MITM")
    def do_ip_forwarding(self, _: argparse.Namespace):
        """
        Enable transparent IP packet forwarding between two targets.
        Usage: Intercepts and re-routes packets while maintaining connectivity.
        Parameters: Requires 'ip_dst', 'eth_dst', 'ip_src' (gateway), and 'eth_src'.
        """
        if not self.tools.get('ip_forwarding'):
            self.poutput('IPforwarding module is unavailable!')
            return
        self.tools['ip_forwarding'].ws = self.workspaces
        self.tools['ip_forwarding'].args = self.args_obj
        self.tools['ip_forwarding'].start_tool()

    # --- Category: Utilities ---

    @cmd2.with_category("Utilities")
    def do_raw_packet(self, _: argparse.Namespace):
        """
        Load and transmit a raw hex-encoded packet from a file.
        Usage: Set 'input' to the path of the .hex or .txt file containing the raw hex stream.
        Example: set input packets/malformed_dhcp.hex
        """
        if not self.tools.get('raw_packet'):
            self.poutput('RAWpacket module is unavailable!')
            return
        self.tools['raw_packet'].ws = self.workspaces
        self.tools['raw_packet'].args = self.args_obj
        self.tools['raw_packet'].start_tool()
        