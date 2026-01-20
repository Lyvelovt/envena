from scapy.all import IP, ICMP
from scapy.all import sniff, conf, get_if_addr, get_if_hwaddr
from time import monotonic

from src.envena.functions import get_mac, parse_ip_ranges
from src.envena.base.arguments import Arguments, public_args
from src.envena.base.tool import Tool
from src.modules.ethernet.ip.icmp import ICMPPacket, ICMPPacketType
from random import randint
# from src.envena.base.address import IPaddrType

def packet_callback(packet, logger):
    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return
    
    if packet[ICMP].type == 0:
        logger.info('Echo reply got! Summing up info...')
    
    elif packet[ICMP].type == 11:
        # logger.info(f"Time exceeted from {packet[IP].src}")
        pass
    # packet.summary()
    # Вернуть True, чтобы остановить sniff() после обработки первого пакета


def is_way_exists(param, logger, my_ip, my_eth, eth_dst, ip, icmp_id=randint(1,65535)):
    ICMPPacket(
        iface=param.iface,
        count=1,
        timeout=0,
        ip_src=my_ip,
        ip_dst=param.ip_dst,
        eth_src=my_eth,
        eth_dst=eth_dst,
        packet_type=ICMPPacketType.ECHO_REQUEST,
        seq=1,
        icmp_id=icmp_id,
        ttl=255
        ).send_packet(printed=0)
            
    result = sniff(
        filter=f"icmp and ((icmp[4:2] == {icmp_id}) or (icmp[0] == 11 and dst host {my_ip}))",
        timeout=1.2,
        count=1,
        prn=lambda pkt: packet_callback(packet=pkt, logger=logger),
        iface=param.iface,
    )
    if len(result) == 0 or result[0][ICMP].type != 0:
        logger.error(f'No way on {ip}')
        return False
    return True

def icmpmap(param, logger, ws=None):
    try:
        my_eth = get_if_hwaddr(param.iface)
        my_ip = get_if_addr(param.iface)
        ip_range = parse_ip_ranges(param.input)
        hops = {}
        for ip in ip_range:
            ip = str(ip)
            logger.info(f'Asking for {ip} MAC-address, waiting 1 sec.')
            eth_dst = get_mac(target_ip=str(ip), iface=param.iface)
            if not eth_dst:
                # logger.error(f'No answer from {ip}')
                continue
            else:
                logger.info('Succesfully got ARP response')
            icmp_id = randint(1,65535)
            got_reply = False
            way_exists = False
            for _ in range(0,3):
                if is_way_exists(param=param, logger=logger, my_ip=my_ip,
                                 my_eth=my_eth, eth_dst=eth_dst, ip=ip):
                    way_exists = True
                    break
            if not way_exists:
                break
            
            hops[ip] = []
            
            for ttl in range(1, 256):
                if got_reply:
                    break
                
                for sent_packets in range(0, 3):
                    logger.info(f'{sent_packets+1}...Sent echo-request with TTL={ttl}, ')
                    start_echo = monotonic()
                    ICMPPacket(
                        iface=param.iface,
                        count=1,
                        timeout=0,
                        ip_src=my_ip,
                        ip_dst=param.ip_dst,
                        eth_src=my_eth,
                        eth_dst=eth_dst,
                        packet_type=ICMPPacketType.ECHO_REQUEST,
                        seq=sent_packets,
                        icmp_id=icmp_id,
                        ttl=ttl
                    ).send_packet(printed=0)
                    
                    result = sniff(
                        filter=f"icmp and ((icmp[4:2] == {icmp_id}) or (icmp[0] == 11 and dst host {my_ip}))",
                        timeout=1,
                        count=1,
                        prn=lambda pkt: packet_callback(packet=pkt, logger=logger),
                        iface=param.iface,
                        )
                                    
                    if len(result) == 0:
                        logger.warning("Timeout: no response received.")
                        continue
                    
                    end_echo = monotonic()
                    
                    pkt = result[0]
                    if pkt[ICMP].type == 11:
                        hops[ip].append((pkt[IP].src, end_echo - start_echo))
                        break

                    elif pkt[ICMP].type == 0:
                        hops[ip].append((pkt[IP].src, end_echo - start_echo))
                        got_reply = True
                        break
        # print(hops)
        for ip in hops:
            logger.info(f'Trace {ip} -> {param.ip_dst}:')
            for i in range(0, len(hops[ip])):
                logger.info(f'Hop {i+1}...: ip: {hops[ip][i][0]}, time: {round(hops[ip][i][1], 4)} sec.')
                        # print(hops)
                            # break   
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    
t_icmpmap = Tool(tool_func=icmpmap, VERSION=1.4)
        
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
        
        # args=Arguments()
        
        public_args.iface = cli_args.iface
        public_args.ip_dst = cli_args.ip_dst
        public_args.input = cli_args.ip
        
        t_icmpmap.start_tool()
        
    except KeyboardInterrupt:
        exit()