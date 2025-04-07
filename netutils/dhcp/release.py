import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import random

def send_dhcp_release(ip_src: str, ip_dst: str, xid: int, hostname: str=None, iface: str=None,
                      mac_src: str=None, port_src: int=68, printed: bool=True)->bool:
    
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
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=port_src, dport=67)
    bootp = BOOTP(chaddr=mac_src.encode(), xid=xid)

    dhcp_options = [
        ("message-type", 7),  # DHCP Release
        ("client_id", b"\x01" + bytes.fromhex(mac_src.replace(":", ""))),
        ("server_id", ip_dst),
        ("requested_addr", ip_src),
        ("hostname", hostname), # Optional, but can be included.
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp
    
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
