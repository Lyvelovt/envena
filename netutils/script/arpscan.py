import random

import scapy.all as scapy

from .dns_getHostname import get_hostname

import sys
sys.path.append('..'*2)
from config import *

def print_aligned_table(table):
    headers = list(table[0].keys())

    max_lengths = {}
    for header in headers:
        max_lengths[header] = len(header)
        for row in table:
            if header in row:
                max_lengths[header] = max(max_lengths[header], len(str(row[header])))

    header_names = ["IP", "MAC", "HOSTNAME"]

    header_row = " | ".join(header_names[i].ljust(max_lengths[headers[i]]) for i in range(len(header_names)))
    print(header_row)
    print("-" * len(header_row))  

    for row in table:
        row_values = [str(row.get(header, "")).ljust(max_lengths[header]) for header in headers]
        print(" | ".join(row_values))

def get_mac(ip_dst, ip_src, mac_src):
    """Получает MAC-адрес устройства по его IP-адресу."""
    arp_request = scapy.ARP(pdst=ip_dst, psrc=ip_src, hwsrc=mac_src)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def scan_network(ip_range, ip_src=None, mac_src=None):
    anim_num = 0
    anim = '/|\\-'
    # Сканирует сеть для обнаружения устройств и их IP, MAC и DNS.
    devices = []
    num = 0
    random.shuffle(ip_range)
    for ip in ip_range:
        mac = get_mac(ip_dst=ip, mac_src=mac_src, ip_src=ip_src)
        if mac:
            hostname = get_hostname(ip)
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname
            })
        num += 1
        anim_num += 1
        if(anim_num > 3):
            anim_num = 0
        print(f'Scanning({num}/{len(ip_range)})... {anim[anim_num]}\r', end='')

    print(' '*22 + '\r', end='')

    return devices


def arpscan(args):
    start_time = time.time()
    if '-' in args['payload']:
        ip = args['payload'].split('-')
        ip[0] = ip[0].split('.')
        ip_range = [f"{ip[0][0] + '.' + ip[0][1] + '.' + ip[0][2]}." + str(i) for i in
                    range(int(ip[0][3]), 1 + int(ip[1]))]
    else:
        ip = args['payload'].split('.')
        ip_range = [f"{ip[0] + '.' + ip[1] + '.' + ip[2]}." + str(i) for i in
                    range(int(ip[3]), 1 + int(ip[3]))]
    print("ARP-Scanner, version: 1.0")
    print('*Scanning started')
    devices_info = scan_network(ip_range=ip_range, mac_src=args['mac_src'], ip_src=args['ip_src'])
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

        desc = '''ARP-Scanner is a Local Area Network scanner that using ARP. Version: 2.0\n
        \n
        base using:
          arpscan -ip <192.168.1.10-20>  will scan from 192.168.1.10 to 192.168.1.20
          arpscan -ip <192.168.1.10>     will scan only 192.168.1.10
        '''

        parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("ip", help="target IP or range.")  # , required=True)
        # parser.add_argument( "-i", "--interface", help="Network interface.")

        args = parser.parse_args()
        print("ARP-Scanner, version: 1.0.")
        print('Scanning started.')
        if '-' in args.ip:
            args.ip = args.ip.split('-')
            args.ip[0] = args.ip[0].split('.')
            ip_range = [f"{args.ip[0][0] + '.' + args.ip[0][1] + '.' + args.ip[0][2]}." + str(i) for i in range(int(args.ip[0][3]), 1 + int(args.ip[1]))]
        else:
            args.ip = args.ip.split('.')
            ip_range = [f"{args.ip[0]+ '.' + args.ip[1] + '.' + args.ip[2]}." + str(i) for i in range(int(args.ip[3]), 1 + int(args.ip[3]))]
            try:
                devices_info = scan_network(ip_range)
            except KeyboardInterrupt:
                print('Successfully aborted.')
                exit()
        if devices_info:
            print(f'Scan finished in {round(time.time() - start_time, 3)} s.')
            print('Detected device(s):')
            print_aligned_table(devices_info)
        else:
            print("Failed to detect device(s) on the network.")
    except(KeyboardInterrupt):
        print('Successfully aborted.')
        exit()