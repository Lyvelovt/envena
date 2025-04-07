import scapy.all as scapy
from scapy.all import Ether

import sys, os
sys.path.append(os.path.join('..', '..'))
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

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="ARP-spoofing atack detect module.")
    parser.add_argument("-i", "--iface", help="Network iface to sniff from.", required=False)
    parser.add_argument("-f", "--file", help="The hexdump file to send", required=True)

    arg = parser.parse_args()
    send_raw_packet(payload=arg.file, iface=arg.iface)