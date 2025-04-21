import random
import scapy.all as scapy
import socket
import time
import sys, os
sys.path.append(os.path.join('..','..'))
from config import *
from oui import *

def get_manufacturer(mac: str)->str:
    if not mac:
        return "Unknown"
    oui = mac.lower().split(":")[:3]  # Берем первые 3 байта
    oui_str = ":".join(oui)
    if oui_str in manufactures:
        return manufactures[oui_str]
    else: return "Unknown"

def get_hostname(ip: str)->str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def print_aligned_table(devices: list)->None:
    if not devices:
        return
    
    max_ip = max(max(len(d["ip"]) for d in devices), len("IP"))
    max_mac = max(max(len(d["mac"]) for d in devices), len("MAC"))
    max_host = max(max(len(str(d["hostname"])) for d in devices), len("HOSTNAME"))
    max_manuf = max(max(len(str(get_manufacturer(d["mac"]))) for d in devices), len("MANUFACTURER"))
    
    headers = [
        f"{'IP':<{max_ip}}",
        f"{'MAC':<{max_mac}}",
        f"{'HOSTNAME':<{max_host}}",
        f"{'MANUFACTURER':<{max_manuf}}"
    ]
    print("  ".join(headers))
    
    sep = "  ".join([
        "-" * max_ip,
        "-" * max_mac,
        "-" * max_host,
        "-" * max_manuf
    ])
    print(sep)
    
    for device in devices:
        hostname = device.get("hostname", "-")
        manufacturer = get_manufacturer(device["mac"]) or "-"
        
        row = [
            f"{device['ip']:<{max_ip}}",
            f"{device['mac']:<{max_mac}}",
            f"{hostname:<{max_host}}",
            f"{manufacturer:<{max_manuf}}"
        ]
        print("  ".join(row))

def scan_network(ip_range: str, ip_src: str=None, mac_src: str=None, iface: str=scapy.conf.iface, timeout: int=4)->list:
    devices = []
    answered = []
    
    # Filter out our own IP
    self_ip = ip_src if ip_src else scapy.get_if_addr(iface)
    target_ips = [ip for ip in ip_range if ip != self_ip]
    random.shuffle(target_ips)
    
    # ARP sniff callback
    def arp_callback(pkt):
        if pkt[scapy.ARP].op == 2:  # is-at (response)
            answered.append(pkt)
    
    # Start sniffing in background
    sniff_filter = "arp"
    sniffer = scapy.AsyncSniffer(prn=arp_callback, filter=sniff_filter, store=0)
    sniffer.start()
    
    # Send all ARP requests at once
    arp_request = scapy.ARP(pdst=target_ips, psrc=ip_src or scapy.get_if_addr(iface), hwsrc=mac_src)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    scapy.sendp(broadcast/arp_request, verbose=False)
    
    # Wait for responses
    print(f'Scanning(0...{len(target_ips)})... \r', end='')
    time.sleep(timeout)
    sniffer.stop()
    
    # Process responses
    for pkt in answered:
        ip = pkt[scapy.ARP].psrc
        mac = pkt[scapy.ARP].hwsrc
        hostname = get_hostname(ip)
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname
        })
    
    print(f'Scanning({len(target_ips)}/{len(target_ips)})   ')
    print(' '*22 + '\r', end='')
    
    return devices

def arpscan(args: dict)->None:
    if not validate_args(ip_src=args['ip_src'], mac_src=args['mac_src'], iface=args['iface'], timeout=args['timeout']): return False
    start_time = time.time()
    if '-' in args['input']:
        ip = args['input'].split('-')
        ip[0] = ip[0].split('.')
        ip_range = [f"{ip[0][0] + '.' + ip[0][1] + '.' + ip[0][2]}." + str(i) for i in
                    range(int(ip[0][3]), 1 + int(ip[1]))]
    else:
        ip = args['input'].split('.')
        ip_range = [f"{ip[0] + '.' + ip[1] + '.' + ip[2]}." + str(i) for i in
                    range(int(ip[3]), 1 + int(ip[3]))]
    
    print("ARP-Scanner, version: 1.0")
    print('*Scanning started')
    devices_info = scan_network(ip_range=ip_range, mac_src=args['mac_src'], ip_src=args['ip_src'], iface=args['iface'], timeout=int(args['timeout']))
    
    if devices_info:
        print(f'Scan finished in {round(time.time() - start_time, 3)} s.')
        print('Detected device(s):')
        print_aligned_table(devices_info)
    else:
        print("Failed to detect device(s) on the network.")

if __name__ == "__main__":
    try:
        import time
        start_time = time.time()
        
        import argparse

        desc = '''ARP-Scanner is a Local Area Network scanner that using ARP. Version: 2.1
        
        base using:
          python3 arpscan.py -ip <192.168.1.10-20>  # will scan from 192.168.1.10 to 192.168.1.20
          python3 arpscan.py -ip <192.168.1.10>     # will scan only 192.168.1.10
        '''

        parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("-ip", help="target IP or range.", required=True)
        parser.add_argument("-t", "--timeout", help="waiting time for responses in seconds.", required=False)
        
        arg = parser.parse_args()
        arg.timeout = 3 if not arg.timeout else arg.timeout

        args = {'input': arg.ip, 'timeout': arg.timeout, 'mac_src': scapy.get_if_hwaddr(scapy.conf.iface), 'ip_src': scapy.get_if_addr(scapy.conf.iface), 'iface': scapy.conf.iface}
        arpscan(args)
    except(KeyboardInterrupt):
        print('Successfully aborted.')
        exit()
