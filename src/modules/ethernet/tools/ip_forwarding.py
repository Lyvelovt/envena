from scapy.all import IP, Ether, sendp
from scapy.all import PcapWriter, sniff, conf, get_if_addr, get_if_hwaddr
from datetime import datetime

from src.envena.functions import get_mac
from src.envena.base.arguments import Arguments
from src.envena.base.tool import Tool
# from src.envena.base.address import IPaddrType
import ipaddress

ARP_TABLE = {}

def check_subnet_membership(ip_to_check: str, local_interface_cidr: str) -> bool:
    local_network = ipaddress.ip_network(local_interface_cidr, strict=False)
    
    return ipaddress.ip_address(ip_to_check) in local_network


def addr_spoof(packet, my_ip, my_eth, gateway_mac, netmask, logger, iface):
    global ARP_TABLE
    
    if not (packet.haslayer(IP) and packet.haslayer(Ether)):
        return

    if packet[IP].ttl == 1 or packet[Ether].src == my_eth:
        return
    
    if packet[IP].dst != my_ip and packet[Ether].dst == my_eth:
        if check_subnet_membership(packet[IP].dst, f'{my_ip}{netmask}'):
            if packet[IP].dst in ARP_TABLE:
                packet[Ether].dst = ARP_TABLE[packet[IP].dst]
            else:
                got_mac = get_mac(packet[IP].dst, iface)
                logger.info('Destination IP-address not in ARP table. ARP request sent')
                if not got_mac:
                    logger.error(f'Unknown destination IP-address in IP title. Packet was dropped')
                    return
                ARP_TABLE[packet[IP].dst] = got_mac
                packet[Ether].dst = ARP_TABLE[packet[IP].dst]
                logger.info(f'Succesfully got destionation IP-address')
        else:
            packet[Ether].dst = gateway_mac
        
        packet[Ether].src = my_eth
    
        packet[IP].ttl -= 1
    
        del packet[IP].chksum
    
        sendp(packet, iface=iface, verbose=0)
        logger.info(f'{packet[IP].src} -> {packet[IP].dst}')
    

def ip_forwarding(param, logger):
    my_eth = get_if_hwaddr(param.iface)
    my_ip = get_if_addr(param.iface)
    gateway_mac = str(param.eth_dst).replace('-',':')
    netmask = param.input
    
    now = datetime.now()
    filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'

    try:
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except Exception:
        filename = f'ip_forwarding_{now.strftime("%Y%m%d_%H%M%S")}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)

    forwarded_packets = sniff(prn=lambda pkt: addr_spoof(packet=pkt, my_ip=my_ip, my_eth=my_eth, 
                                                        gateway_mac=gateway_mac, netmask=netmask, 
                                                        logger=logger, iface=param.iface), store=False, iface=param.iface)
    pcap_writer.write(forwarded_packets)
    logger.info(f'Traffic was written in "{filename}"')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"IP-forwarding module")
    # parser.add_argument("--ip_dst", "-id", help="Destination IP address (victim).", required=True)
    # parser.add_argument("--eth_dst", "-ed", help="Destination MAC address (victim).", required=True)
    parser.add_argument("--gateway", "-g", help="gateway MAC-address", required=True, type=str)
    parser.add_argument("--netmask", "-nm", help="mask of your network (default: '/24')", required=False, type=str, default='/24')
    parser.add_argument("-i", "--iface", help="Network interface to send from.", required=False, type=str, default=conf.iface)

    cli_args = parser.parse_args()
    
    args=Arguments()
    
    args.iface = cli_args.iface
    args.eth_dst = cli_args.gateway
    args.input = cli_args.netmask
    
    
    t_ip_forwarding = Tool(tool_func=ip_forwarding, VERSION=1.3, args=args)
    t_ip_forwarding.start_tool()
