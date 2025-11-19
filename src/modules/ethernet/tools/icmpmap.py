from scapy.all import IP, Ether, sendp
from scapy.all import PcapWriter, sniff, conf, get_if_addr, get_if_hwaddr
from datetime import datetime

from src.envena.functions import get_mac, parse_ip_ranges
from src.envena.base.arguments import Arguments
from src.envena.base.tool import Tool
from src.modules.ethernet.ip.icmp import ICMPPacket, ICMPPacketType
from random import randint
# from src.envena.base.address import IPaddrType
import ipaddress



def icmpmap(param, logger):
    my_eth = get_if_hwaddr(param.iface)
    my_ip = get_if_addr(param.iface)
    ip_range = parse_ip_ranges(param.input)
    
    for ip in ip_range:
        eth_dst = get_mac(target_ip=ip, iface=param.iface)
        for ttl in range(1, 256):
            ICMPPacket(
                iface=param.iface,
                count=1,
                timeout=0,
                ip_src=my_ip,
                ip_dst=param.ip_dst,
                eth_src=my_eth,
                eth_dst=eth_dst,
                packet_type=ICMPPacketType.ECHO_REQUEST,
                seq=0,
                indef=randint(1, 65535),
                ttl=ttl
            )
    

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"ICMP-map module")
    # parser.add_argument("--ip_dst", "-id", help="Destination IP address (victim).", required=True)
    # parser.add_argument("--eth_dst", "-ed", help="Destination MAC address (victim).", required=True)
    parser.add_argument("-id", "--ip_dst", help="destination IP-address", required=True, type=str)
    parser.add_argument("-ip", "--ip", help="IP-address(es) range of subnetwork", required=True, type=str)
    parser.add_argument("-i", "--iface", help="network interface to send from", required=False, type=str, default=conf.iface)
    # parser.add_argument('-nt', '--nottl', help='do not reduce TTL when forwarding a packet (may cause loops)', action='store_true')

    cli_args = parser.parse_args()
    
    args=Arguments()
    
    args.iface = cli_args.iface
    args.ip_dst = cli_args.ip_dst
    args.input = cli_args.ip
    
    
    t_ip_forwarding = Tool(tool_func=ip_forwarding, VERSION=1.4, args=args)
    t_ip_forwarding.start_tool()
