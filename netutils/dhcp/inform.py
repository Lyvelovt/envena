import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import random

def send_dhcp_inform(ip_src: str, ip_dst: str, xid: int=None, hostname: str=None, iface: str=None, mac_src: str=None,
                     port_src: int=68, port_dst: int=67, printed: bool=True, parameter_request_list: list=None)->bool:
    
    if xid is None:
        xid = random.randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
    elif xid == 'rand_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        random.shuffle(xid)

    port_src=68 if not port_src else port_src
    port_dst=67 if not port_dst else port_dst

    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_src)
    ip = IP(src=ip_src, dst=ip_dst)
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(chaddr=mac_src.encode(), xid=xid)

    if parameter_request_list is None:
      parameter_request_list = [1, 3, 15, 6]

    dhcp_options = [
        ("message-type", 8),  # DHCP Inform
        ("client_id", b"\x01" + bytes.fromhex(mac_src.replace(":", ""))),
        ("server_id", ip_dst),
        ("requested_addr", ip_src),
        #("hostname", hostname),
        ("param_req_list", parameter_request_list),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp

    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"[{iface}] DHCP inform: {ip_src} -> {ip_dst}: Inform {ip_src}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
        
