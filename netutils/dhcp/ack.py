import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import random

def send_dhcp_ack(ip_dst: str, ip_src: str, mac_dst: str, xid: int, lease_time: int=3600, sub_mask: str="255.255.255.0",
                   ip_router: str=None, dns_server: str="8.8.8.8", iface: str=None, mac_src: str=None,
                   port_src: int=67, printed: bool=True)->bool:

    if ip_router is None:
        ip_router = ip_src
    
    try:
        lease_time = int(lease_time)
    except ValueError:
        lease_time = 360
    
    if xid is None:
        xid = random.randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
        
    ether = Ether(dst=mac_dst, src=mac_src)
    ip = IP(src=ip_src, dst=ip_dst)
    udp = UDP(sport=port_src, dport=68)
    bootp = BOOTP(op=2, yiaddr=ip_dst, chaddr=mac_dst.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 5),  # DHCP ACK
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
                f"[{iface}] DHCP ack: {ip_src} -> {ip_dst}: Address issue acknowledgement")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False 
