# This file contains commands that the user can use. 
# Use this file to add your modules, arguments, commands, etc. 
# This file is used by the file "envena.py " and it will affect 
# all other files and modules.

# Import libs
import time
import os
from random import randint
import inspect
import platform
from typing import Dict

# Import o
from .banner import envena_art 
from .help import help_info
from .config import Clear, Error, Success, Error_text,\
    main_exit, scapy, envena_version

# Import all modules:
# ARP #======================================#
from src.modules.ethernet.arp.request import send_arp_request
from src.modules.ethernet.arp.response import send_arp_response
# READY-MADE TOOLS #=========================#
from src.modules.ethernet.tools.arpscan import arpscan
from src.modules.ethernet.tools.dns_getHostname import dns_getHostname
from src.modules.ethernet.tools.detect_arpspoof import detect_arpspoof
from src.modules.ethernet.tools.dhcp_starve import dhcp_starve
from src.modules.ethernet.tools.camoverflow import cam_overflow
# RAW PACKET SENDER #========================#
from src.modules.ethernet.tools.raw_packet import send_raw_packet
#IP FORWARDING #=============================#
from src.modules.ethernet.tools.ip_forward import ip_forward # this shit does not working for now
# DHCP #=====================================#
from src.modules.ethernet.dhcp.discover import send_dhcp_discover
from src.modules.ethernet.dhcp.ack import send_dhcp_ack
from src.modules.ethernet.dhcp.offer import send_dhcp_offer
from src.modules.ethernet.dhcp.request import send_dhcp_request
from src.modules.ethernet.dhcp.nak import send_dhcp_nak
from src.modules.ethernet.dhcp.release import send_dhcp_release
from src.modules.ethernet.dhcp.inform import send_dhcp_inform
# DOT11 #====================================#
from src.modules.dot11.tools.dot11scan import dot11scan
from src.modules.dot11.tools.dot11trilateration import dot11trilateration
# DATABASE #=================================#
# import sqlite3
# database/oui.db
# FUNCTIONS #================================#
from .functions import rand_ip, rand_eth, get_manufacturer, get_sub_ip, get_ip_broadcast

# Contains the packet headers. When sending a packet, 
# it is checked for its presence in this dictionary.
packet_handlers = {
    'arp.response': send_arp_response,
    'arp.request': send_arp_request,
    'dhcp.discover': send_dhcp_discover,
    'dhcp.offer': send_dhcp_offer,
    'dhcp.request': send_dhcp_request,
    'dhcp.ack': send_dhcp_ack,
    'dhcp.inform': send_dhcp_inform,
    'dhcp.release': send_dhcp_release,
    'dhcp.nak': send_dhcp_nak,
    'raw_packet': send_raw_packet,
    # ...
}

# Dict thath consists of command that uses in Envena's interactive shell
commands = {
    "exit": lambda: main_exit(),
    "help": lambda: print(help_info),
    "?": lambda: print(help_info), 
    "list": lambda: list_dict(args),
    "clear": lambda: os.system('cls' if platform.system == 'Windows' else 'clear'),
    "list clear": lambda: list_clear(),
    "minfo": lambda: get_manufacturer(args['input'], printed=True),
    "arp.request": lambda: send_packet(type='arp.request', args=args),
    "arp.response": lambda: send_packet(type='arp.response', args=args),
    "dhcp.discover": lambda: send_packet(type='dhcp.discover', args=args), 
    "dhcp.offer": lambda: send_packet(type='dhcp.offer', args=args),
    "dhcp.ack": lambda: send_packet(type='dhcp.ack', args=args),
    "dhcp.nak": lambda: send_packet(type='dhcp.nak', args=args),
    "dhcp.release": lambda: send_packet(type='dhcp.release', args=args),
    "dhcp.request": lambda: send_packet(type='dhcp.request', args=args),
    "dhcp.inform": lambda: send_packet(type='dhcp.inform', args=args),
    "tools.arpscan": lambda: arpscan(args=args),
    "tools.dns_getHostname": lambda: dns_getHostname(args=args),
    "tools.detect_arpspoof": lambda: detect_arpspoof(args=args),
    "tools.ip_forward": lambda: ip_forward(args=args),
    "tools.raw_packet": lambda: send_packet(type='raw_packet', args=args),
    "tools.dhcp_starve": lambda: dhcp_starve(args=args),
    "tools.cam_overflow": lambda: cam_overflow(args=args),
    "tools.dot11trl": lambda: dot11trilateration(args=args),
    "tools.dot11scan": lambda: dot11scan(args=args),
    "uinfo": lambda: get_my_info()
    # ...
}

# All arguments
args = {
    'ip_dst': None,
    'ip_src': None,
    'eth_dst': None,
    'eth_src': None,
    'port_dst': None,
    'port_src': None,
    'count': 1,
    'timeout': 1,
    'iface': scapy.conf.iface,
    'input': None,
    'sub_mask': "255.255.255.0",
    'sub_ip': None,
    'xid': None,
    'dns_server': '8.8.8.8',
    # ...
}
# Calculate the subnet address based on own IP
args['sub_ip'] = get_sub_ip(mask=args['sub_mask'], host_ip=scapy.get_if_addr(args['iface']))

# Dict that consists of words that will be reserved for constants or functions.
# They can be used by entering their names in the shell or by passing them as a
# value to the function input. 
tech_words = {
    "None": lambda: None,
    "my_ip": lambda: scapy.get_if_addr(args['iface']),
    "my_eth": lambda: scapy.get_if_hwaddr(args['iface']),
    "eth_bcast": lambda: "ff:ff:ff:ff:ff:ff",
    "ip_bcast": lambda: get_ip_broadcast(host_ip=scapy.get_if_addr(args['iface']), mask=args['sub_mask']),
    "rand_eth": lambda: rand_eth(args['input']),
    "rand_ip": lambda: rand_ip(args['input']),
    "rand_xid": lambda: randint(0, 0xFFFFFFFF),
    "rand_port": lambda: randint(1, 65535),
    "eth_noaddr": lambda: '00:00:00:00:00:00',
    "ip_noaddr": lambda: '0.0.0.0'
    # ...
    
}

# Lists with dictionary arguments that specify the format of the variable value (integer, IP or MAC address, etc.)
args_int_list = 'timeout', 'count', 'xid', 'port_src', 'port_dst'
args_ip_list = 'ip_src', 'ip_dst', 'dns_server', 'sub_mask', 'sub_ip'
args_eth_list = 'eth_src', 'eth_dst'

# List that consists all users interfaces names
ifaces_list = scapy.get_if_list()



# FUNTIONS SECTION #============================================#

def get_my_info()->None:
    print(
        "*-={USER INFO}=-*\n"
        f"Founded interfaces......: {', '.join(ifaces_list)}\n"
        f"Interface as default....: {scapy.conf.iface}\n"
        f"Own eth-address.........: {scapy.get_if_hwaddr(args['iface'] if args['iface'] in scapy.get_if_list() else scapy.conf.iface)}\n"
        f"Own IP-address..........: {scapy.get_if_addr(args['iface'] if args['iface'] in scapy.get_if_list() else scapy.conf.iface)}\n"
        f"Envena version..........: {envena_version}\n"
        f"Program running as root.: {True if os.getuid() == 0 else False}"
        )
    
# Animated-print art
def print_art()->None:
    for line in envena_art:
        print(line)
        time.sleep(0.02)

# Send packeges according to count, timeout, type of package and e.t.c.
def send_packet(type: str, args: Dict)->bool:
    global packet_handlers
    dot_timer = 0 # For animated '...' output
    word_timer = 0 # For animated 'Sending' output
    word_sending = 'sending' # Word that will be animated while sending...
    sent_packets = 0
    count = args['count']
    timeout = args['timeout']
    handler = packet_handlers.get(type)
    if not handler:
        print(f'{Error}Error:{Clear} {Error_text}unknown packet type: {type}{Clear}')
        return False

    handler_params = inspect.signature(handler).parameters
    
    filtered_args = {k: v for k, v in args.items() if k in handler_params}
    current = count if count > 0 else float('inf') # If count < 0 then the cycle 
    first = True # Flag that indicating the first run through the cycle
    while current:
        print(word_sending[:word_timer] + word_sending[word_timer].upper() + word_sending[word_timer+1:] + '.' * dot_timer, end='\r')
        if handler(**filtered_args, printed=first): # Send package
            sent_packets += 1
        if not first:
            time.sleep(timeout)
        dot_timer += 1
        dot_timer %= 4 # Cycle the timer from 0 to 3
        word_timer += 1
        word_timer %= 7
        current -= 1
        first = False
        print(word_sending[:word_timer] + word_sending[word_timer].upper() + word_sending[word_timer+1:]+' '*3, end='\r\r')
    print(f"\n\r{Success}{sent_packets} packet(s) sent.{Clear}")
    return True

# Stuffing dict by 'None' value
def list_clear()->None:
    global args
    for _ in args:
        if _ == 'iface': continue
        args[_] = None

# Print dict as pretty-good table :)
def list_dict(args: dict, title: str="*-={ARGS LIST}=-*")->None:
    max_size = 0
    for arg in args:
        max_size = max(len(arg), max_size)
    max_size += 1
    print(title)
    for arg in args:
        print(f'{arg}{'.'*(max_size-len(arg))}: {args[arg]}')
        
# Input with arrow's history
def history_input(prompt: str='')->str:
    while True:
        line = input(prompt)
        if line:
            return line