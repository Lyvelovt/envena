import struct

import scapy.all as scapy
from scapy.all import Ether

import sys
sys.path.append('..')
from config import *


def send_raw_packet(payload=None, iface=None, printed=True):
    # Создаем raw socket
    with open(payload, 'r') as pkt_file:
        payload = pkt_file.read()
        payload = bytes.fromhex(payload)
    # Привязываем сокет к интерфейсу, если он указан
    packet = Ether(payload)
    try:
        scapy.sendp(payload, verbose=False, iface=iface)
        if printed: scapy.hexdump(payload)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False

# Пример использования
if __name__ == "__main__":
    file = 'packet.hex'
    send_raw_packet(payload=file, iface='en0')
    # Отправляем пакет
    #send_raw_packet(packet, interface="en0")  # Укажите ваш интерфейс