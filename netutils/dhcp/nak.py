import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys
sys.path.append('..'*2)
from config import *

import random

def send_dhcp_nak(ip_src, ip_dst, xid, mac_src, iface=None, mac_dst=None, port_src=67,
                printed=True, lease_time=3600, sub_mask='255.255.255.0', ip_router=None, dns_server='8.8.8.8'):
    
    if ip_router is None:
        ip_router = ip_src
    
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

    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_src) # Server's MAC address. Best to fill this in if known
    ip = IP(src=ip_src, dst="255.255.255.255")
    udp = UDP(sport=port_src, dport=68)
    bootp = BOOTP(chaddr=mac_dst.encode(), xid=xid)

    dhcp_options = [
        ("message-type", 6),  # DHCP NAK
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
                f"{Back}[{Purple}{iface}{Clear}{Back}] DHCP nak: {Orange}{ip_src}{Clear}{Back} -> {Blue}{mac_dst}{Clear}{Back}: {Dark_light_blue}Refused to issue {Blue}{ip_dst}{Clear}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
        
    
