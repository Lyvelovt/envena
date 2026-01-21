# from src.envena.core.address import IPaddrType
import ipaddress
from datetime import datetime

from scapy.all import (IP, Ether, PcapWriter, conf, get_if_addr, get_if_hwaddr,
                       sendp, sniff)

from src.envena.core.arguments import Arguments, public_args
from src.envena.core.basetool import BaseTool
from src.envena.modules.ethernet.sniff import CATEGORY_DOC
from src.envena.utils.functions import get_mac

ARP_TABLE = {}


def check_subnet_membership(ip_to_check: str, local_interface_cidr: str) -> bool:
    local_network = ipaddress.ip_network(local_interface_cidr, strict=False)

    return ipaddress.ip_address(ip_to_check) in local_network


def addr_spoof(packet, my_ip, my_eth, gateway_mac, submask, logger, iface, nottl=False):
    global ARP_TABLE

    if not (packet.haslayer(IP) and packet.haslayer(Ether)):
        return

    if packet[Ether].src == my_eth:
        return

    if packet[IP].ttl <= 1 and not nottl:
        logger.info("TTL ended, packet was dropped")
        return

    if packet[IP].dst != my_ip and packet[Ether].dst == my_eth:
        if check_subnet_membership(packet[IP].dst, f"{my_ip}/{submask}"):
            if packet[IP].dst in ARP_TABLE:
                packet[Ether].dst = ARP_TABLE[packet[IP].dst]
            else:
                got_mac = get_mac(packet[IP].dst, iface)
                logger.info("Destination IP-address not in ARP table. ARP request sent")
                if not got_mac:
                    logger.error(
                        f"Unknown destination IP-address in IP title. Packet was dropped"
                    )
                    return
                ARP_TABLE[packet[IP].dst] = got_mac
                packet[Ether].dst = ARP_TABLE[packet[IP].dst]
                logger.info(f"Succesfully got destionation IP-address")
        else:
            packet[Ether].dst = gateway_mac

        packet[Ether].src = my_eth

        packet[IP].ttl -= 1

        del packet[IP].chksum

        sendp(packet, iface=iface, verbose=0, count=1)
        logger.info(f"{packet[IP].src} -> {packet[IP].dst}")


def ip_forwarding(param, logger, ws=None):
    my_eth = get_if_hwaddr(param.iface)
    my_ip = get_if_addr(param.iface)
    gateway_mac = str(param.eth_dst).replace("-", ":")
    submask = param.sub_mask
    nottl = True if param.input == "nottl" else False

    # filter_str = f"ip and not host {my_ip} and not ether src {my_eth}"

    now = datetime.now()
    filename = f"ip_forwarding_{now.strftime('%Y%m%d_%H%M%S')}.pcap"

    try:
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except Exception:
        # filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)

    forwarded_packets = sniff(
        prn=lambda pkt: addr_spoof(
            packet=pkt,
            my_ip=my_ip,
            my_eth=my_eth,
            gateway_mac=gateway_mac,
            submask=submask,
            logger=logger,
            iface=param.iface,
            nottl=nottl,
        ),
        store=False,
        iface=param.iface,
    )
    #   filter=filter_str)
    pcap_writer.write(forwarded_packets)
    logger.info(f'Traffic was written in "{filename}"')


class t_ip_forwarding(BaseTool):
    """
    Transparent IP forwarding between victims and gateway.

    Arguments:
        gateway (Required): MAC address of the gateway (e.g. aa:bb:cc...).
        submask (Optional): Network mask (default: /24).
        nottl (Optional): If set, doesn't decrement IP TTL (prevents loops).
        iface (Optional): Interface to forward on.

    Example:
        args set gateway 00:0c:29:4f:b1:15
        ip_forwarding
    """

    def __init__(self, tool_func=ip_forwarding, VERSION=1.4):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=f"IP-forwarding module")
    # parser.add_argument("--ip_dst", "-id", help="Destination IP address (victim).", required=True)
    # parser.add_argument("--eth_dst", "-ed", help="Destination MAC address (victim).", required=True)
    parser.add_argument(
        "--gateway", "-g", help="gateway MAC-address", required=True, type=str
    )
    parser.add_argument(
        "--submask",
        "-sm",
        help="subnet mask of your network (default: '/24')",
        required=False,
        type=str,
        default="/24",
    )
    parser.add_argument(
        "-i",
        "--iface",
        help="network interface to send from",
        required=False,
        type=str,
        default=conf.iface,
    )
    parser.add_argument(
        "-nt",
        "--nottl",
        help="do not reduce TTL when forwarding a packet (may cause loops)",
        action="store_true",
    )

    cli_args = parser.parse_args()

    # args=Arguments()

    public_args.iface = cli_args.iface
    public_args.eth_dst = cli_args.gateway
    public_args.sub_mask = cli_args.submask
    public_args.input = "nottl" if cli_args.nottl else ""

    t_ip_forwarding().start_tool()
