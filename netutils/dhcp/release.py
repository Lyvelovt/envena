import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import random

def send_dhcp_release(ip_src: str, ip_dst: str, xid: int = random.randint(1000000, 9999999), iface: str=None,
                      mac_src: str=None, port_src: int=68, port_dst: int=67, printed: bool=True)->bool:
    

    port_src=68 if not port_src else port_src
    port_dst=67 if not port_dst else port_dst    
    
    if isinstance(xid, str):
        xid = int(xid)
    elif xid == 'rand_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        random.shuffle(xid)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_src) / \
                IP(src="0.0.0.0", dst="255.255.255.255") / \
                UDP(sport=port_src, dport=port_dst) / \
                BOOTP(
                    op=1,
                    chaddr=bytes.fromhex(mac_src.replace(":", "")),
                    ciaddr=ip_src,
                    xid=xid
                ) / \
                DHCP(options=[
                    ("message-type", "release"),
                    ("client_id", b"\x01" + bytes.fromhex(mac_src.replace(":", ""))),
                    ("server_id", ip_dst),
                    ("requested_addr", ip_src),
                    "end"
                ])
    
    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        
        if printed:
            print(
                f"[{iface}] DHCP release: {ip_src} -> {ip_dst}: {ip_src} has been released")
            scapy.hexdump(packet)
        
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
