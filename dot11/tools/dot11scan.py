from datetime import datetime
import sys
import os
sys.path.append(os.path.join('..','..'))
from config import scapy, Clear, Success, scapy, envena_version
from scapy import PcapWriter, sniff, Dot11
from functions import validate_args
import platform
dot11scan_v = 1.0

aps = {}
cnt = 0
def get_eth_in_package(pkt)->None:
    os.system('cls' if platform.system == 'Windows' else 'clear')
    if pkt.haslayer(Dot11):
        dot11 = pkt[Dot11]

        if dot11.type == 2:  # Data frame
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3

            # Типичная логика: клиент ↔ AP
            if bssid and src and dst:
                if bssid not in aps:
                    aps[bssid] = set()
                if src != bssid:
                    aps[bssid].add(src)
                if dst != bssid:
                    aps[bssid].add(dst)
                print(f'\t\t\t[ {datetime.now()} ] ENVENA{envena_version} DOT11 SCANER{'.'*cnt}')
                print('\tAP\t\t\tCLIENT')
                for ap in aps:
                    print(f'\t{ap}')
                    for client in aps[bssid]:
                        print(f'\t  \t\t\t{client}')
                cnt += 1
                cnt %= 4
                os.system('cls' if platform.system == 'Windows' else 'clear')

def dot11scan(args: dict)->None:
    os.system('cls' if platform.system == 'Windows' else 'clear')
    if not validate_args(iface=args['iface']): return False
    print(f'Dot11scan, version: {dot11scan_v}')
    print('*Scanning started. Ctrl+C to stop')
    now = datetime.now()
    
    filename = f'captured/envena_dot11scan_{now}.pcap'
    try:
        filename = f'captured/envena_dot11scan_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except FileNotFoundError:
        filename = f'envena_dot11scan_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    arpspoof_packets = sniff(iface=args['iface'], prn=get_eth_in_package, store=True)
    pcap_writer.write(arpspoof_packets)
    print('\nAbort.')
    print(f'\n{Success}Traffic was writted in \'{filename}\'{Clear}')
 

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"Dot11 scanner module. Version: {dot11scan_v}")
    parser.add_argument("-i", "--iface", help="Network iface to sniff from.", required=False)

    arg = parser.parse_args()
    args = {}
    args['iface'] = arg.iface if arg.iface is not None else scapy.conf.iface
    dot11scan(args)
