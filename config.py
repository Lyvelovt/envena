import time
import os
import inspect

# Word that always print with exit
bye_word = 'Bye-bye! Quiting...'
envena_version = 1.0

# Colors
if os.name == "posix":
    # For Unix-like
    Clear = "\033[0m"
    Error = "\033[31m"
    Fatal_Error = "\033[1;31m"
    Success = "\033[32m"
    Error_text = "\033[3;31m"
    Info = "\033[43m"
    Back = "\033[48;5;236m"
    Muted = "\033[37m"
    Back_red = "\033[101m"

    Blink = "\033[5m"
    Blue = "\033[38;5;117m"
    Orange = "\033[38;5;208m"
    Purple = "\033[95m"
    Light_blue = "\033[96m"
    Dark_light_blue = "\033[36m"
    Light_red = "\033[38;5;197m"

    # For ART:
    x = '\033[1m'
    y = '\033[1;31m'
    w = '[90m'
    r = '[0;0;0m'
    g = '[30m'
    n = '[37m'
    c = Clear
else:
    # For not Unix-like
    Clear = ""
    Error = ""
    Fatal_Error = ""
    Success = ""
    Error_text = ""
    Info = ""
    Back = ""
    Back_red = ""
    Muted = ""

    Blink = ""
    Blue = ""
    Orange = ""
    Purple = ""
    Light_blue = ""
    Dark_light_blue = ""
    Light_red = ""

    # For ART:
    x = ''
    y = ''
    w = ''
    r = ''
    g = ''
    n = ''
    c = Clear


from random import randint
import readline
from typing import Dict, Union




# Exit if scapy is not installed

try:
    import scapy.all as scapy

except ModuleNotFoundError:
    print(f"{Fatal_Error}\'Scapy\' must been installed. Try: \'pip3 install scapy\'{Clear}")
    print(bye_word)
    exit()

# Importing all modules:
# ARP #======================================#
from netutils.arp.request import *
from netutils.arp.response import *
# READY-MADE toolsS #=======================#
from netutils.tools.arpscan import *
from netutils.tools.dns_getHostname import *
from netutils.tools.detect_arpspoof import *
from netutils.tools.dhcp_starve import *
from netutils.tools.camoverflow import *
#RAW PACKET SENDER #=========================#
from netutils.tools.raw_packet import *
#IP FORWARDING #=============================#
from netutils.tools.ip_forward import *
# DHCP #=====================================#
from netutils.dhcp.discover import *
from netutils.dhcp.ack import *
from netutils.dhcp.offer import *
from netutils.dhcp.request import *
from netutils.dhcp.nak import *
from netutils.dhcp.release import *
from netutils.dhcp.inform import *



# Color for main-menu art

envenena_art = [
    f'      {w}..?{n}5{w}??.?5??...                  ',
    f'  {g}c{w}??.?{n}5{w}???5{n}5{w}???5{n}@{w}5??5..c                ',
    f'  {w}5..?555??{n}55{w}5??{n}5@{w}555{n}@{w}5???c              ',
    f' {w}c555?5{n}55{w}5{n}5@5{w}55{n}5@@{w}55{n}5@5{w}5?5{n}5{w}?.            ',
    f'{g}c{w}?{n}5@5{w}5{n}55555@5{w}55{n}5@5@@@@{w}555{n}5@{w}5??c          ',
    f'{w}55{n}@@@55@55@5{w}5{n}555@5@@@@5{w}55{n}@5{w}555{n}5?{w}c        ',
    f'{w}5{n}@@@@{w}5{n}5@5@@5@@5@@5@@@@555{n}@{w}555{n}@@{w}???c      ',
    f'{w}?{n}@5{w}?5?..5{n}@@@@@@@@@@@@@@@55{n}5{w}5{n}5@@{w}55?{n}5{w}.         {y}<---Envena!!!{r}',
    f'{w}???       c{n}55@@@@@@@@@@@@@@@@@55{w}5{n}5@5{w}?    ',
    f'{w}?          {w}55{n}5@@@%@@@@@@@5@@@@{w}5{n}5{w}5{n}@5{w}555        {Muted}~~version: {envena_version}~~{r}',
    f'           {w}?{n}@@@ {w}c.{n}5%@%%@5@@@@@@5@@{w}55{n}5{w}5?      {y}by Lyvelovt Studio{r}',
    f'           {w}?{n}%%{w}.    ?{n}@@@@@%@@@@@@@@{w}55{n}@{w}5?.     {y}https://github.com/Lyvelovt{r}',
    f'           {w}?{n}@{g}c     {w}c{n}@5@@{w}?5{n}@@@@@5@@@5@@@{w}?.    {y}https://github.com/Lyvelovt/envena.git{r}',
    f'                   {g}c{n}@@@{w}.  {g}c{w}5{n}@@@%@@@5{w}5{n}@@{w}??',
    f'                   {w}.{n}%@{w}?     ?{n}@@@5@@@@@5{w}5?',
    f'                   {w}?5       {w}.{n}@@@{w}c{g}c{w}?{n}@@@@@{w}?    #{Muted + x}Network packages manipulation{r}',
    f'                   {g}c         {n}@@5    {w}?{n}5@%{w}.    {Muted + x}utility.{r}',
    f'                            {g}c{n}@@{w}c      ?5     #{Muted + x}Use \'?\' or \'help\' for help info.{r}',
    f'                             {w}5{g}c          ',
    f'                             {w}c{r}           '
]


# Help info that print with 'help' or '?'
help_info = """
Envenena v1.0.

Available commands:
arp.request         -    send ARP-request.
arp.response        -    send ARP-reply.
dhcp.discover       -    send DHCP-discover.
dhcp.offer          -    send DHCP-offer.
dhcp.request        -    send DHCP-request.
dhcp.ack            -    send DHCP-ack.
dhcp.nak            -    send DHCP-nak.
dhcp.release        -    send DHCP-release.
raw_packet          -    send bytes from file.
dhcp.info           -    send DHCP-info.
list                -    Show all value of args.
exit                -    Exit from program.
help                -    Show this text.
?                   -    The same as 'help'.

Ready-made toolss:
arp_scan             -    scanning network using ARP protocol. Input ip
                            range must be in 'input' and use format 'x.x.x.x-255'.
                            Output is IP|MAC|HOSTNAME.
dns_getHostname     -    Send DNS protocol request. Get hostname by IP-address.
                            Output is variable of hostname.
detect_arpspoof     -    sniffs traffic and detects packets with duplicate addresses,
                            which may indicate ARP spoofing.


Available args:
ip_dst        -    destination-IP address.
ip_src        -    source IP-address, by default - your IP address.
port_dst      -    destination port.
port_src      -    source port.
mac_dst       -    destination MAC-address.
mac_src       -    source MAC-address, by default - your MAC-address.
count         -    count of packets to send.
timeout       -    timeout between sending packets in seconds.
interface     -    network interface.
input       -    input or specific input data for module.
sub_mask      -    sudnet mask. Default = 255.255.255.0.
xid           -    XID for DHCP packets.
ip_router     -    router's IP-address.
mac_router    -    router's MAC-address.
dns_server    -    DNS server for getting IP-address from domen.
                    Default = 8.8.8.8 (Google Public DNS).
hostname      -    source/destination hostname.

Information:
1. By default all args is 'None'. 'None' source arg contains your information.
That is, if 'ip_src=None' (this applies to the rest of the arguments,
not just ip_src), then the packet will be sent under your IP-address.
2. You can leave the value of the arg empty, in this case it will 
take the value zero. That is, if 'ip.src=', then the sender's address in 
the packet will be specified as 0x00.0x00.0x00.0x00, in other words, 'no address'.

MAC-address info:
List of the initial 3 octets of the mac address by manufacturer:
--------         -----------------------------------
00:15:f2    -    ASUSTek COMPUTER INC.
00:0a:f5    -    Airgo Networks, Inc. (now Qualcomm)
00:08:22    -    InPro Comm (now MediaTek)
00:50:56    -    VMware, Inc.
00:05:69    -    Cisco-Linksys LLC
00:0a:95    -    Apple, Inc.
00:1b:4f    -    HUAWEI TECHNOLOGIES CO.,LTD
00:23:69    -    Intel Corporate
00:24:d7    -    Samsung Electronics Co.,Ltd
00:25:9c    -    Dell Inc
00:a0:c9    -    Compaq Computer Corporation
00:d0:f8    -    Riverbed Technology, Inc.
00:19:e2    -    zte corporation
00:10:18    -    Juniper Networks, Inc.
--------         -----------------------------------

### MODULES INFO ###
arp.request:
    ip_dst      -       the IP address of the device whose MAC address is being requested.
    ip_src      -       source IP address.
    mac_dst     -       destination MAC address. By default - use "broadcast".
    mac_src     -       source MAC-address.
arp.response:
    ip_dst      -       destination IP address. By default - use "ip_broadcast"
    ip_src      -       source IP address, who is telling his MAC address.
    mac_dst     -       destination MAC address. By default - use "broadcast".
    mac_src     -       source MAC-address, that will be telling.
dhcp.discover:
    port_src    -       UDP port which the package will be sent from
    mac_src     -       source MAC address.
    xid         -       transaction's XID.
    hostname    -       source hostname.
dhcp.ack:
    ...
"""

# ARGS SECTION #================================================#

# Dict that consists of net-packets types. 
# You can add your packet-module and add to this dict.

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
    "clear": lambda: print("\033[H\033[J", end=""),
    "list clear": lambda: list_clear(),
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
    'ip_router': None,
    'mac_router': None,
    'dns_server': '8.8.8.8',
    'hostname': None,
    # ...
}


# FUNTIONS SECTION #============================================#

def get_my_info()->None:
    print(
        "*-={USER INFO}=-*\n"
        f"Founded interfaces......: {', '.join(scapy.get_if_list())}\n"
        f"Interface as default....: {scapy.conf.iface}\n"
        f"Own MAC-address.........: {scapy.get_if_hwaddr(scapy.conf.iface)}\n"
        f"Own IP-address..........: {scapy.get_if_addr(scapy.conf.iface)}\n"
        f"Envena version..........: {envena_version}\n"
        f"Program running as root.: {True if os.getuid() == 0 else False}"
        )

def main_exit()->None:
    print(bye_word)
    exit()

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
    
# [Tech-word] Return random XID

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

# [Base] Interactive shell handler
def process_input(user_input: str)->None:
    global args
    user_input = user_input.strip()
    
    if '=' in user_input:
        parts = user_input.split('=', 1)
        if len(parts) == 2:
            name, value = parts[0].strip(), parts[1].strip()
            if name not in args:
                print(f'{Error}Error:{Clear} {Error_text}arg "{name}" is incorrect.{Clear}')
            elif value in args:
                args[name] = args[value]
            else:
                handler = tech_words.get(value)
                if handler: args[name] = handler()
                else: args[name] = value
        else:
            print(f'{Error}Error:{Clear} {Error_text}incorrect argument assignment format. Use "name=value"{Clear}')
    else:
        handler = commands.get(user_input)
        tech_handler = tech_words.get(user_input)
        if handler:
            handler()
        elif user_input in args:
            print(args[user_input])
        elif tech_handler:
            print(tech_handler())
        else:
            print(f'{Error}Error:{Clear} {Error_text}unknown command. Use "help" to see help info.{Clear}')



