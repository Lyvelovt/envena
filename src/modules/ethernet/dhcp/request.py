import sys
import os
sys.path.append(os.path.join('..','..'))
from src.envena.config import scapy, Error_text, Fatal_Error, Clear
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from src.envena.functions import validate_args, randint
from random import shuffle

import random

def send_dhcp_request(ip_src: str, ip_dst: str, xid: int, hostname: str=None, iface: str=None,
                      eth_src: str=None, port_src: int=68, port_dst: int=67, printed: bool=True)->bool:

    port_src=68 if not port_src else port_src
    port_dst=67 if not port_dst else port_dst
    
    if xid is None:
        xid = randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
    elif xid == 'ex_search_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        shuffle(xid)
    if not validate_args(ip_src=ip_src, ip_dst=ip_dst, xid=xid, iface=iface,
                      eth_src=eth_src, port_src=port_src, port_dst=port_dst):
        return False
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(chaddr=eth_src.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 3),  # DHCP Request
        ("client_id", b"\x01" + bytes.fromhex(eth_src.replace(":", ""))),
        ("requested_addr", ip_src),
        ("server_id", ip_dst),
        #("hostname", hostname),
        ("param_req_list", [1, 3, 15, 6]),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp
    
    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"[{iface}] DHCP request: {ip_src} -> 255.255.255.255: Requested address accepted. {ip_src} is at {eth_src}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
