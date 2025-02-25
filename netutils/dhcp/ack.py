import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

import sys
sys.path.append('..'*2)
from config import *

import random

def send_dhcp_ack(ip_dst, ip_src, mac_dst, xid, lease_time=3600, sub_mask="255.255.255.0",
                   ip_router=None, dns_server="8.8.8.8", iface=None, mac_src=None, port_src=67, printed=True):

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
                f"{Back}[{Purple}{iface}{Clear}{Back}] DHCP ack: {Orange}{ip_src}{Clear}{Back} -> {Blue}{ip_dst}{Clear}{Back}: {Dark_light_blue}Address issue acknowledgement{Clear}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False 
