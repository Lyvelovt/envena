# from src.envena.config import scapy, Error_text, Fatal_Error, Clear
# from src.envena.functions import validate_args
from scapy.all import ARP, hexdump, Ether, sendp
import logging

def send_arp_request(param, printed=True)->bool:
    ip_src = str(param.ip_src)
    ip_dst = str(param.ip_dst)
    eth_src = str(param.eth_src).replace('-', ':')
    eth_dst = str(param.eth_dst).replace('-', ':')
    iface = str(param.iface)
    
    arp_request = ARP(
        pdst=ip_dst,  # Destination IP address (who are we asking)
        psrc=ip_src, # Sender IP address (who is asking)
        hwsrc=eth_src, # Sender MAC address (who is asking)
        hwdst=eth_dst,  # Broadcast MAC for the request
        op="who-has" # ARP request
    )

    # Creates an Ethernet packet for the data link layer
    ether = Ether(src=eth_src, dst=eth_dst)  # Broadcast MAC

    # Combines the two packets into one
    packet = ether/arp_request

    # Sends the packet
    try:
        sendp(packet, iface=iface, verbose=False)
        if printed:
            param.logger.info(f"Sent request: {ip_src} -> {eth_dst}: who has {ip_dst}? Tell {ip_src}")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False

