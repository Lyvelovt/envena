import scapy.all as scapy

import sys
sys.path.append('..'*2)
from config import *


def send_arp_response(ip_dst, mac_dst, ip_src, mac_src, iface, printed=True):
    """Sends an ARP reply with the specified parameters."""
    if not validate_args(ip_dst=ip_dst, ip_src=ip_src, mac_src=mac_src, mac_dst=mac_dst): return False


    if mac_dst == 'broadcast':
        mac_dst = 'ff:ff:ff:ff:ff:ff'
    if mac_src == 'broadcast':
        mac_src = 'ff:ff:ff:ff:ff:ff'

    # Creates an ARP packet
    arp_reply = scapy.ARP(
        pdst=ip_dst,  # Destination IP address (who are we sending the reply to)
        hwdst=mac_dst,  # Destination MAC address
        psrc=ip_src,  # Sender IP address (spoofed IP)
        hwsrc=mac_src,  # Sender MAC address (spoofed MAC)
        op="is-at" # Set that is ARP reply
    )

    # Creates an Ethernet packet for the data link layer
    ether = scapy.Ether(src=mac_src, dst=mac_dst)

    # Combines the two packets into one
    packet = ether/arp_reply
    # Sends the packet
    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"[{iface}] Sent ARP response: {ip_src} -> {ip_dst}: {ip_src} is at {mac_src}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False



if __name__ == "__main__":
    try:
        import time
        start_time = time.time()
        
        import argparse
        parser = argparse.ArgumentParser(description="Sending ARP reply.")
        parser.add_argument("--ip_dst", "-di", help="Destination IP address (default = \"Broadcast\". It is not needed if the mode is \"is-at\").", required=False)
        parser.add_argument("--mac_dst", "-dm", help="Destination MAC address. Broadcast == \"ff:ff:ff:ff:ff:ff\".", required=False)
        parser.add_argument("--ip_src", "-si", help="Sender (spoofed) IP address (default = your IP address).", required=True)
        parser.add_argument("--mac_src", "-sm", help="Sender (spoofed) MAC address (default = your MAC address).", required=False)
        parser.add_argument("-i", "--iface", help="Network iface to send from.", required=True)
        parser.add_argument("-r", "--range", help="Number of packages to send (infinite = -1, default = 1).", type=int, required=False)
        parser.add_argument("-it", "--interval", help="Time interval between sending packets in seconds (default = 0).", type=int, required=False)



        args = parser.parse_args()
        # Return to default if None
        if args.ip_src == None: args.ip_src = scapy.get_if_addr(args.iface)
        if args.mac_src == None: args.mac_src = scapy.get_if_hwaddr(args.iface)
        if args.interval == None: args.interval = 0
        if args.range == None: args.range = 1
        if args.mac_dst == None or args.mac_dst.lower() == 'broadcast': args.mac_dst = 'ff:ff:ff:ff:ff:ff'
        # if args.mac_dst == 'ff:ff:ff:ff:ff:ff': args.ip_dst = f'{Light_red}Broadcast{Clear}'
        if args.interval < 0:
            print(f'{Error}Error:{Clear} {Error_text}interval can\'t be negative.{Clear}')
            exit(0)

        # Flags, counters and animation
        anim_num = 0
        anim = '/|\\-'
        num = 0
        recv_num = 0
        lost_num = 0
        if args.mac_dst == 'ff:ff:ff:ff:ff:ff':
            print(f"{Back}Sent ARP response: {Orange}{args.ip_src}{Clear}{Back} -> {Light_red}Broadcast{Clear}{Back}: {Orange}{args.ip_src}{Clear}{Back} {Purple}is at{Clear}{Back} {Light_blue}{args.mac_src}{Clear}{Clear}")
        else:
            print(f"{Back}Sent ARP response: {Orange}{args.ip_src}{Clear}{Back} -> {Blue}{args.mac_dst if args.ip_dst == None else args.ip_dst}{Clear}{Back}: {Orange}{args.ip_src}{Clear}{Back} {Purple}is at{Clear}{Back} {Light_blue}{args.mac_src}{Clear}{Clear}")
        while num < args.range or args.range < 0:

            if anim_num > 3:
                anim_num = 0

            print(f'Sending({num}/{args.range if args.range > 0 else '~'})... {anim[anim_num]}\r', end='')

            try:
                send_arp_reply(args.ip_dst, args.mac_dst, args.ip_src, args.mac_src, args.iface)

                recv_num += 1
                if num + 1 != args.range: time.sleep(args.interval)

            except KeyboardInterrupt:
                print('')
                break

            except Exception as e:
                print(f"{Error}Send error:{Clear} {Error_text}{e}{Clear}")
                lost_num += 1

            anim_num += 1
            num += 1
            print(' ' * 18 + '\r', end='')


        print(f'-------------------------------------------------------------' + '-'*len(str(num)+str(recv_num)+str(lost_num)+str(round(abs(start_time - time.time()), 3))))
        print(f'{num} packets transmitted, {Success}{recv_num}{Clear} packets received, {Error}{lost_num}{Clear} packets loss at {round(abs(start_time - time.time()), 3)} s.')
    except KeyboardInterrupt:
        print('')
        print(f"\n{Success}Successfully aborted.{Clear}")
        print(f'-------------------------------------------------------------' + '-'*len(str(num)+str(recv_num)+str(lost_num)+str(round(abs(start_time - time.time()), 3))))
        print(f'{num} packets transmitted, {Success}{recv_num}{Clear} packets received, {Error}{lost_num}{Clear} packets loss at {round(abs(start_time - time.time()), 3)} s.')
        exit(0)
    except Exception as e:
        print(f'{Error}Error:{Clear} {Error_text}{e}{Clear}')
