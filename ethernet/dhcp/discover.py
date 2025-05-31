import sys
import os
sys.path.append(os.path.join('..','..'))
from config import scapy, Error_text, Fatal_Error, Clear
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from random import shuffle
from functions import validate_args, randint

def send_dhcp_discover(xid: int=None, hostname: str=None, port_src: int=68, port_dst: int=67,
                       eth_src: str=None, iface: str=None, printed: bool=True)->bool:

    if xid is None:
        xid = randint(1000000, 9999999)
    elif isinstance(xid, str):
        xid = int(xid)
    elif xid == 'ex_search_xid':
        xid = []
        for _ in range(1000000, 9999999):
            xid.append(_)
        shuffle(xid)
    port_src=68 if not port_src else port_src
    port_dst=67 if not port_dst else port_dst
    
    if not validate_args(xid=xid, port_src=port_src, port_dst=port_dst,
                       eth_src=eth_src, iface=iface):
        return False


    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(chaddr=eth_src.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 1),  # DHCP Discover
        ("client_id", b"\x01" + bytes.fromhex(eth_src.replace(":", ""))),
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
                f"[{iface}] DHCP discover: {eth_src} -> 255.255.255.255: Is there any DHCP server here? Tell {eth_src}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False
    
    # return xid 
