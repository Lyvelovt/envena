# This file contains all the commands and modules (sending packets of different protocols
# and ready-made scripts). Use this file to add your modules.
import time
import os
import inspect
import platform
from typing import Dict, Union
from banner import envenena_art
from help import help_info
from oui import manufactures
from config import *
# Importing all modules:
# ARP #======================================#
from netutils.arp.request import *
from netutils.arp.response import *
# READY-MADE toolsS #========================#
from netutils.tools.arpscan import *
from netutils.tools.dns_getHostname import *
from netutils.tools.detect_arpspoof import *
from netutils.tools.dhcp_starve import *
from netutils.tools.camoverflow import *
# RAW PACKET SENDER #========================#
from netutils.tools.raw_packet import *
#IP FORWARDING #============================#
from netutils.tools.ip_forward import *
# DHCP #=====================================#
from netutils.dhcp.discover import *
from netutils.dhcp.ack import *
from netutils.dhcp.offer import *
from netutils.dhcp.request import *
from netutils.dhcp.nak import *
from netutils.dhcp.release import *
from netutils.dhcp.inform import *
# DATABASE #=================================#
from oui import *



# Importing all modules:
# ARP #======================================#
from netutils.arp.request import *
from netutils.arp.response import *
# READY-MADE toolsS #========================#
from netutils.tools.arpscan import *
from netutils.tools.dns_getHostname import *
from netutils.tools.detect_arpspoof import *
from netutils.tools.dhcp_starve import *
from netutils.tools.camoverflow import *
# RAW PACKET SENDER #========================#
from netutils.tools.raw_packet import *
#IP FORWARDING #============================#
from netutils.tools.ip_forward import *
# DHCP #=====================================#
from netutils.dhcp.discover import *
from netutils.dhcp.ack import *
from netutils.dhcp.offer import *
from netutils.dhcp.request import *
from netutils.dhcp.nak import *
from netutils.dhcp.release import *
from netutils.dhcp.inform import *
# DATABASE #=================================#
from oui import *




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
    "maninfo": lambda: print_manufacture(args['input']),
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
    "uinfo": lambda: get_my_info()
    # ...
}


# Dict that consists of words that will be reserved for constants or functions.
# They can be used by entering their names in the shell or by passing them as a
# value to the function input. 
tech_words = {
    "None": lambda: None,
    "my_ip": lambda: scapy.get_if_addr(args['iface']),
    "my_mac": lambda: scapy.get_if_hwaddr(args['iface']),
    "broadcast": lambda: "ff:ff:ff:ff:ff:ff",
    "ip_broadcast": lambda: "255.255.255.255",
    "rand_mac": lambda: rand_mac(),
    "rand_ip": lambda: rand_ip(),
    "rand_xid": lambda: randint(1000000, 9999999),
    # ...

}

args = {
    'ip_dst': None,
    'ip_src': None,
    'mac_dst': None,
    'mac_src': None,
    'port_dst': None,
    'port_src': None,
    'count': 1,
    'timeout': 1,
    'iface': scapy.conf.iface,
    'input': None,
    'sub_mask': "255.255.255.0",
    'xid': None,
    'dns_server': '8.8.8.8',
    # ...
}


# FUNTIONS SECTION #============================================#

def get_my_info()->None:
    print(
        "*-={USER INFO}=-*\n"
        f"Founded interfaces......: {', '.join(scapy.get_if_list())}\n"
        f"Interface as default....: {scapy.conf.iface}\n"
        f"Own MAC-address.........: {scapy.get_if_hwaddr(args['iface'] if args['iface'] in scapy.get_if_list() else scapy.conf.iface)}\n"
        f"Own IP-address..........: {scapy.get_if_addr(args['iface'] if args['iface'] in scapy.get_if_list() else scapy.conf.iface)}\n"
        f"Envena version..........: {envena_version}\n"
        f"Program running as root.: {True if os.getuid() == 0 else False}"
        )

# [Base] Print manufacturer's company
def print_manufacture(mac: str=None)->bool:
    if mac.lower() in manufactures:
        print(f'Manufacture of "{mac}" is {manufactures[mac.lower()]}')
        return True
    else:
        print(f'Failed to find manufacturer of "{mac}" from database.')
        return False

# [Base] Animated-print art
def print_art()->None:
    for line in envenena_art:
        print(line)
        time.sleep(0.02)

# [Tech-word] Returned random MAC-address by mask or not
def rand_mac()->str:
    global args
    mask=args['input']
    if not mask or (mask.count(':') != 5 and len(mask) != 17):
        if mask: print(f'{Error}Error:{Clear} {Error_text}There is not MAC-address mask in \'input\' arg.{Clear}')
        mask = 'xx:xx:xx:xx:xx:xx'
    mask = mask.split(':')
    for i, _ in enumerate(mask, start=0):
        if _ != 'xx': continue
        octet = str(hex(randint(0, 255)))
        if len(octet) < 4:
            mask[i] = '0' + octet[2]
        else:
            mask[i] = octet[2] + octet[3]
    return f"{mask[0]}:{mask[1]}:{mask[2]}:{mask[3]}:{mask[4]}:{mask[5]}"


# [Tech-word] Returned random IP-address by mask or not
def rand_ip()->str:
    global args
    mask=args['input']
    if not mask or (mask.count('.') != 3 or (len(mask) < 7 or len(mask) > 15)):
        if mask: print(f'{Error}Error:{Clear} {Error_text}There is not IP-address mask in \'input\' arg.{Clear}')
        mask = 'x.x.x.x'
    mask = mask.split('.')
    for i, _ in enumerate(mask, start=0):
        if _ != 'x': continue
        mask[i] = str(randint(0, 255))
    return f"{mask[0]}.{mask[1]}.{mask[2]}.{mask[3]}"
    
# [Tech-word] Return shuffled list of all XID's that can be
def ex_search_xid()->list:
    xid = []
    for _ in range(1000000, 9999999):
        xid.append(_)
    random.shuffle(xid)
    return xid
    
# [Base] Send packeges according to count, timeout, type of package and e.t.c.
def send_packet(type: str, args: Dict)->bool:
    global packet_handlers
    timer = 1
    sent_packets = 0
    count = int(args['count'])
    timeout = int(args['timeout'])
    handler = packet_handlers.get(type)
    if not handler:
        print(f'{Error}Error:{Clear} {Error_text}unknown packet type: {type}{Clear}')
        return False

    handler_params = inspect.signature(handler).parameters

    filtered_args = {k: v for k, v in args.items() if k in handler_params}

    for _ in range(count, 0, -1) or count < 0:
        print('Sending' + '.' * timer, end='\r')
        if handler(**filtered_args, printed=(_ == int(args['count']))):
            sent_packets += 1
        if _ != 1: time.sleep(timeout)
        timer += 1
        if timer > 3:
            timer = 1
            print('Sending   ', end='\r\r')
    print(f"{Success}{sent_packets} packet(s) sent.{Clear}")
    return True

# [Command] Stuffing dict by 'None' value
def list_clear()->None:
    global args
    for _ in args:
        args[_] = None

# [Command] Print dict as pretty-good table :)
def list_dict(args: dict, title: str="*-={ARGS LIST}=-*")->None:
    max_size = 0
    for arg in args:
        max_size = max(len(arg), max_size)
    max_size += 1
    print(title)
    for arg in args:
        print(f'{arg}{'.'*(max_size-len(arg))}: {args[arg]}')
        
# [Base] Input with arrow's history
def history_input(prompt: str="<-= ")->str:
    while True:
        line = input(prompt)
        if line:
            # print('\033[F', end='')
            return line


def main_exit()->None:
    print(bye_word)
    exit()

