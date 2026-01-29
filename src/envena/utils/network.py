import ipaddress

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    IP,
    UDP,
    Ether,
    RandShort,
    conf,
    get_if_addr,
    get_if_hwaddr,
    srp1,
    srp,
)


from scapy.all import DNS, DNSQR, IP, UDP, Ether, srp1, conf, RandShort
import ipaddress

def get_hostname(ip: str, iface: str = None, dns_server: str = "8.8.8.8") -> str:
    """Get DNS by IP address using DNS protocol through specific interface.

    Args:
        ip (str): IP address to resolve.
        iface (str): Interface to send from (e.g., 'en0'). Defaults to conf.iface.
        dns_server (str): DNS server to send request.

    Returns:
        Resolved hostname or original IP if resolution fails.
    """
    iface = iface or conf.iface
    ptr_name = ipaddress.ip_address(ip).reverse_pointer

    dns_pkt = (
        Ether() / 
        IP(dst=dns_server) / 
        UDP(sport=RandShort(), dport=53) / 
        DNS(rd=1, qd=DNSQR(qname=ptr_name, qtype="PTR"))
    )

    answer = srp1(dns_pkt, iface=iface, timeout=2, verbose=0)

    if answer and answer.haslayer(DNS) and answer[DNS].ancount > 0:
        res = answer[DNS].an.rdata
        if isinstance(res, bytes):
            return res.decode().strip(".")
        return str(res).strip(".")
        
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
