import socket
from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, sendp, srp

def get_hostname(ip: str) -> str:
    """
    Get DNS by IP address using DNS protocol.
    
    Args:
        ip (str): IP address of looking DNS.
    
    Returns:
        hostname (str): Got DNS or input IP address if it failed to got DNS.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if not hostname or hostname == "":
            return ip
        else:
            return hostname
    except socket.herror:
        return ip
    
def get_mac(
    target_ip: str, iface: str = conf.iface, timeout: float = 1.0
) -> str | None:
    """
    Synchronously get MAC address by IP address using ARP protocol (scapy based).
    
    Args:
        target_ip (str): IP address of looking MAC address.
        iface (str | optional): Iface to send ARP request and get ARP respone from. Default: scapy.conf.iface.
        timeout (float | optional): Timeout to waiting ARP response.
    
    Returns:
        mac_address (str | none): MAC address of target IP address or None if failed to get ARP response.
    """
    eth_src = get_if_hwaddr(iface)
    ip_src = get_if_addr(iface)
    ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
    arp_request = ARP(
        pdst=target_ip, psrc=ip_src
    )  # , hwdst='ff:ff:ff:ff:ff:ff', hwsrc=eth_src, op='who-has')
    # sendp(arp_request, iface='en0')
    answered, unanswered = srp(
        ether_layer / arp_request,
        timeout=timeout,
        iface=iface,
        verbose=0,
        retry=0,
    )

    if answered:
        mac_address = answered[0][1].hwsrc
        return mac_address.lower()

    return None