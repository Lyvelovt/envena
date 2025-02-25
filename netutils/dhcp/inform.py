import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys
sys.path.append('..'*2)
from config import *

import random

def send_dhcp_inform(ip_src, ip_dst, xid=None, hostname='', iface=None, mac_src=None, port_src=68, printed=True, parameter_request_list=None):
    
    if xid is None:
        xid = random.randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
    elif xid == 'rand_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        random.shuffle(xid)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_src)
    ip = IP(src=ip_src, dst=ip_dst) # Changed src and dst IPs
    udp = UDP(sport=port_src, dport=67)
    bootp = BOOTP(chaddr=mac_src.encode(), xid=xid)

    if parameter_request_list is None:
      parameter_request_list = [1, 3, 15, 6]

    dhcp_options = [
        ("message-type", 8),  # DHCP Inform
        ("client_id", b"\x01" + bytes.fromhex(mac_src.replace(":", ""))),
        ("server_id", ip_dst),
        ("requested_addr", ip_src),
        ("hostname", hostname),
        ("param_req_list", parameter_request_list),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp

    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"{Back}[{Purple}{iface}{Clear}{Back}] DHCP inform: {Orange}{ip_src}{Clear}{Back} -> {Blue}{ip_dst}{Clear}{Back}: {Dark_light_blue}Inform {Orange}{ip_src}{Clear}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
        
