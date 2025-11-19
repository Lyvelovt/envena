from scapy.all import IP, Ether, sendp, ICMP
from scapy.all import PcapWriter, sniff, conf, get_if_addr, get_if_hwaddr
from datetime import datetime

from src.envena.functions import get_mac, parse_ip_ranges
from src.envena.base.arguments import Arguments
from src.envena.base.tool import Tool
from src.modules.ethernet.ip.icmp import ICMPPacket, ICMPPacketType
from random import randint
# from src.envena.base.address import IPaddrType
import ipaddress

def packet_callback(packet, logger):
    packet.show()
    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return
    
    if packet[ICMP].type == 0:
        logger.info('Echo reply got! Summing up info...')
    
    elif packet[ICMP].type == 11:
        logger.info(f"Time exceeted from {packet[IP].src}")
    packet.summary()
    # Вернуть True, чтобы остановить sniff() после обработки первого пакета
    return True

def icmpmap(param, logger):
    # try:
    my_eth = get_if_hwaddr(param.iface)
    my_ip = get_if_addr(param.iface)
    ip_range = parse_ip_ranges(param.input)
    # print(my_eth, my_ip, ip_range)
    
    for ip in ip_range:
        eth_dst = get_mac(target_ip=str(ip), iface=param.iface)
        if not eth_dst:
            continue
        icmp_id = randint(1,65535)
        for ttl in range(1, 3):#256):
            for i in range(0,3):
                logger.info(f'{i}...Trying, TTL {ttl}')
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
                    icmp_id=icmp_id,
                    ttl=ttl
                ).send_packet(printed=False)
                result = sniff(
                    filter=f"icmp and icmp[4:2] == {icmp_id}",
                    timeout=1,
                    count=1,
                    prn=lambda pkt: packet_callback(packet=pkt, logger=logger)
                    )
                if len(result) == 1:
                    result[0].show()
                
                
                        # break   
    # except KeyboardInterrupt:
    #     return

if __name__ == '__main__':
    try:
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
        
        
        t_icmpmap = Tool(tool_func=icmpmap, VERSION=1.4, args=args)
        t_icmpmap.start_tool()
    except KeyboardInterrupt:
        exit()