import sys
import os
sys.path.append(os.path.join('..','..'))
from src.envena.config import scapy, Error_text, Fatal_Error, Clear
from src.envena.functions import validate_args

def send_arp_request(ip_dst, eth_dst, ip_src, eth_src, iface, printed=True)->bool:
    if not validate_args(ip_dst=ip_dst, ip_src=ip_src, eth_src=eth_src, eth_dst=eth_dst):
        return False
    if eth_dst == 'broadcast':
        eth_dst = 'ff:ff:ff:ff:ff:ff'
    if eth_src == 'broadcast':
        eth_src = 'ff:ff:ff:ff:ff:ff'
    # Creates an ARP request
    arp_request = scapy.ARP(
        pdst=ip_dst,  # Destination IP address (who are we asking)
        psrc=ip_src, # Sender IP address (who is asking)
        hwsrc=eth_src, # Sender MAC address (who is asking)
        hwdst=eth_dst,  # Broadcast MAC for the request
        op="who-has" # ARP request
    )

    # Creates an Ethernet packet for the data link layer
    ether = scapy.Ether(src=eth_src, dst=eth_dst)  # Broadcast MAC

    # Combines the two packets into one
    packet = ether/arp_request


    # Sends the packet
    try:
        scapy.sendp(packet, iface=iface, verbose=False)
        if printed:
            print(
                f"[{iface}] Sent ARP request: {ip_src} -> {eth_dst}: who has {ip_dst}? Tell {ip_src}")
            scapy.hexdump(packet)
        return True
    except Exception as e:
        print(f"{Fatal_Error}Packet was not sent: {Error_text}{e}{Clear}")
        return False

