import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import random

def send_dhcp_offer(ip_dst: str, ip_src: str, mac_dst: str, xid: int, lease_time: int=3600, sub_mask: str="255.255.255.0",
                    ip_router: str=None, dns_server: str="8.8.8.8", iface: str=None,
                    mac_src: str=None, port_src: int=67, port_dst: int=68, printed: bool=True)->bool:

    if ip_router is None:
        ip_router = ip_src
    
    port_src=67 if not port_src else port_src
    port_dst=68 if not port_dst else port_dst    
    
    try:
        lease_time = int(lease_time)
    except ValueError:
        lease_time = 3600

    if xid is None:
        xid = random.randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
    elif xid == 'rand_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        random.shuffle(xid)

    ether = Ether(dst=mac_dst, src=mac_src)
    ip = IP(src=ip_src, dst=ip_dst)
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(op=2, yiaddr=ip_dst, chaddr=mac_dst.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 2),  # DHCP Offer
        ("server_id", ip_src),
        ("lease_time", lease_time),
        ("sub_mask", sub_mask),
        ("router", ip_router),
        ("dns", dns_server),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp

    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"[{iface}] DHCP offer: {ip_src} -> {mac_dst}: {ip_dst} is free. {mac_dst} can get it")
            scapy.hexdump(packet)

        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False