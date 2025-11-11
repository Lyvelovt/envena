import time
# import sys
import asyncio
# import os
import math
from random import uniform
from src.envena.config import scapy, Error, Error_text, Clear
from src.envena.functions import get_hostname, get_vendor, validate_args, validate_ip
# from src.envena.commands import tech_words
from random import shuffle
arpscan_v = 2.1

from rich.table import Table
from rich.console import Console

def print_aligned_table(devices: list) -> None:
    if not devices:
        return
    
    console = Console()
    table = Table(show_header=True, header_style="bold cyan")

    table.add_column("IP", style="green", justify="left")
    table.add_column("Ethernet", style="magenta", justify="left")
    table.add_column("Hostname", style="yellow", justify="left")
    table.add_column("Vendor", style="blue", justify="left")

    for device in devices:
        hostname = device.get("hostname", "-")
        manufacturer = get_vendor(eth=device["eth"], printed=False) or "-"
        
        table.add_row(
            device["ip"],
            device["eth"],
            hostname,
            manufacturer
        )

    console.print(table)


def scan_network(ip_range: str, ip_src: str=None, eth_src: str=None, iface: str=scapy.conf.iface, timeout: int=4)->list:
    devices = []
    answered = []
    # Filter out our own IP
    # self_ip = ip_src if ip_src else scapy.get_if_addr(iface)
    target_ips = [ip for ip in ip_range if ip != ip_src]
    shuffle(target_ips)
    
    # ARP sniff callback
    def arp_callback(pkt):
        if pkt[scapy.ARP].op == 2:  # is-at (response)
            answered.append(pkt)
    
    # Start sniffing in background
    timeout_coeff = timeout / len(target_ips)
    
    sniff_filter = "arp"
    sniffer = scapy.AsyncSniffer(iface=iface, prn=arp_callback, filter=sniff_filter, store=0)
    
    sniffer.start()
    
    for ip in target_ips:
        scapy.sendp(
                scapy.Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src) /
                scapy.ARP(pdst=ip,
                          psrc=ip_src,
                          hwsrc=eth_src),
                verbose=False, iface=iface)
        print(f'Processing {ip}...  \r', end='')
        delay = timeout_coeff + uniform(-timeout_coeff / 3, timeout_coeff / 3)
        time.sleep(delay)
    print(' '*29, end='\r')  
        # arp_request = scapy.ARP(pdst=ip, psrc=ip_src, hwsrc=eth_src)
        # print(arp_request)
    # broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.sendp(broadcast/arp_request, verbose=False)
    
    # Wait for responses
    # print(f'Scanning(1..{len(target_ips)})... \r', end='')
    # time.sleep(timeout)
    sniffer.stop()
    
    # Process responses
    for pkt in answered:
        ip = pkt[scapy.ARP].psrc
        eth = pkt[scapy.ARP].hwsrc
        hostname = get_hostname(ip)
        devices.append({
            "ip": ip,
            "eth": eth,
            "hostname": hostname
        })
    
    print(f'Scanning({len(target_ips)}/{len(target_ips)})   ')
    print(' '*22 + '\r', end='')
    deduplicated_devices = [dict(t) for t in set(tuple(d.items()) for d in devices)]
    return deduplicated_devices

def arpscan(args: dict)->None:
    if not validate_args(
        input=args['input'], ip_src=args['ip_src'],
        eth_src=args['eth_src'], iface=args['iface'],
        timeout=args['timeout']):
        return False
    
    # invalid_ip is a flag to validate IP
    invalid_ip = False
    if not validate_ip(ip=args['input']):
        if not '-' in args['input']:
            invalid_ip = True
        elif validate_ip(ip=args['input'].split('-')[0]):
            
            for char in args['input'].split('-')[1]:
                    if not char in '0123456789':
                        invalid_ip = True
                        break
            if args['input'].split('-')[1] == '':
                invalid_ip = True
            if not invalid_ip:
                if int(args['input'].split('-')[1]) > 255:
                    invalid_ip = True
        else:
            invalid_ip = True

    if invalid_ip:
        print(f'{Error}Error: {Error_text}arg "input" is invalid! Must be IP (or IP range) in arg "input".{Clear}')
        return False
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
    
    print(f"ARP-Scanner, version: {arpscan_v}")
    print('*Scanning started')
    devices_info = scan_network(ip_range=ip_range, eth_src=args['eth_src'], ip_src=args['ip_src'], iface=args['iface'], timeout=int(args['timeout']))
    
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

        desc = f'''ARP-Scanner is a Local Area Network scanner use ARP protocol. Version: {arpscan_v}
        
        base using:
          python3 arpscan.py -ip <192.168.1.10-20>  # will scan from 192.168.1.10 to 192.168.1.20
          python3 arpscan.py -ip <192.168.1.10>     # will scan only 192.168.1.10
        '''

        parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("-ip", help="target IP or range.", required=True)
        parser.add_argument("-t", "--timeout", help="waiting time for responses in seconds.", required=False)
        parser.add_argument("-i", "--iface", help="interface to scanning from.", required=False)
        
        cli_args = parser.parse_args()
        cli_args.timeout = 3 if not cli_args.timeout else cli_args.timeout
        cli_args.iface = scapy.conf.iface if not cli_args.iface else cli_args.iface

        args = {'input': cli_args.ip, 'timeout': cli_args.timeout, 'eth_src': scapy.get_if_hwaddr(cli_args.iface), \
            'ip_src': scapy.get_if_addr(cli_args.iface), 'iface': cli_args.iface}
        arpscan(args)
    except(KeyboardInterrupt):
        print('Aborted.')
        exit()
