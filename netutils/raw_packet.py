import scapy.all as scapy
from scapy.all import Ether

import sys, os
sys.path.append(os.path.join('..'))
from config import *


def send_raw_packet(payload: str=None, iface: str=None, printed: bool=True)->bool:
    with open(payload, 'r') as pkt_file:
        payload = pkt_file.read()
        payload = bytes.fromhex(payload)
    try:
        scapy.sendp(payload, verbose=False, iface=iface)
        if printed: scapy.hexdump(payload)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False