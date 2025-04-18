import scapy.all as scapy
from scapy.all import Ether

import sys, os
sys.path.append(os.path.join('..', '..'))
from config import *


def send_raw_packet(input: str=None, iface: str=None, printed: bool=True)->bool:
    with open(input, 'r') as pkt_file:
        input = pkt_file.read()
        input = bytes.fromhex(input)
    try:
        scapy.sendp(input, verbose=False, iface=iface)
        if printed: scapy.hexdump(input)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Raw packet send module.")
    parser.add_argument("-i", "--iface", help="Network iface to send from.", required=False)
    parser.add_argument("-f", "--file", help="The hexdump file to send", required=True)

    arg = parser.parse_args()
    send_raw_packet(input=arg.file, iface=arg.iface)