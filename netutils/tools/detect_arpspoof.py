import scapy.all as scapy
from scapy.all import ARP
from scapy.all import PcapWriter, sniff
from datetime import datetime

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *


arp_table = {}
arp_table[scapy.get_if_addr(scapy.conf.iface)] = scapy.get_if_hwaddr(scapy.conf.iface)


def detect_arpspoof_in_package(packet, iface: str=scapy.conf.iface)->None:
    global arp_table
    global is_continue
    if packet.haslayer(ARP):
        if packet[ARP].op == 2: # ARP Response
            print(f"[{iface}] ARP response: {packet[ARP].psrc} -> {packet[ARP].pdst}: {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
            if packet[ARP].psrc in arp_table:
                if arp_table[packet[ARP].psrc] != packet[ARP].hwsrc:
                    print(f"{Fatal_Error}#|!|# ARP Spoofing detected!{Clear}")
                    print(f"   \\ Dublicate IP address detected: {packet[ARP].psrc} is at {packet[ARP].hwsrc} ({packet[ARP].psrc} also in use by {arp_table[packet[ARP].psrc]})")
            else:
                arp_table[packet[ARP].psrc] = packet[ARP].hwsrc
        elif packet[ARP].op == 1:
            print(f"[{iface}] ARP request: {packet[ARP].psrc} -> {packet[ARP].hwdst}: who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")

def detect_arpspoof(args: dict)->None:
    print('ARP-spoof detecter, version: 1.0')
    print('*Sniffing started. Ctrl+C to stop')
    now = datetime.now()
    
    filename = f'captured/envena_detect_arpspoof_{now}.pcap'
    try:
        filename = f'captured/envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except FileNotFoundError:
        filename = f'envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, appd=False, sync=True)
    arpspoof_packets = sniff(filter="arp", prn=detect_arpspoof_in_package, store=True, iface=args['iface'])
    pcap_writer.write(arpspoof_packets)
    print('\nAbort.')
    print(f'\n{Success}Traffic was writted in \'{filename}\'{Clear}')
 

if __name__ == '__main__':
    arpspoof_packets = sniff(filter="arp", prn=detect_arpspoof_in_package, store=True)
    print(arpspoof_packets)