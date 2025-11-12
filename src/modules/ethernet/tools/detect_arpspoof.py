from datetime import datetime
from scapy.all import ARP, conf, get_if_hwaddr
from scapy.all import PcapWriter, sniff
from src.envena.base.arguments import Arguments
from src.envena.base.tool import Tool

arp_table = {}


def detect_arpspoof_in_package(logger, packet)->None:
    global arp_table
    if packet.haslayer(ARP):
        if packet[ARP].op == 2: # ARP Response
            logger.info(f"ARP response: {packet[ARP].psrc} -> {packet[ARP].pdst}: {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
            if packet[ARP].psrc in arp_table:
                if arp_table[packet[ARP].psrc] != packet[ARP].hwsrc:
                    logger.warn("ARP-spoofing detected!")
                    logger.warn(f"Dublicate IP address detected: {packet[ARP].psrc} is at {packet[ARP].hwsrc} ({packet[ARP].psrc} also in use by {arp_table[packet[ARP].psrc]})")
            else:
                arp_table[packet[ARP].psrc] = packet[ARP].hwsrc
        elif packet[ARP].op == 1:
            logger.info(f"ARP request: {packet[ARP].psrc} -> {packet[ARP].hwdst}: who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")

def detect_arpspoof(param, logger)->None:
    param.iface = conf.iface if not param.iface else param.iface
    global arp_table
    arp_table[param.iface] = get_if_hwaddr(param.iface)
    
    if arp_table[param.iface] == '00:00:00:00:00:00':
        logger.error('Invalid interface got. Are you use VPN wright now?')
        logger.info(f'Selected interface "{param.iface}" has "00:00:00:00:00:00" MAC-address, that is not allowed for ethernet traffic')
        logger.info('Hint: try turn off VPN or select enother interface')
        return None
    
    now = datetime.now()
    
    filename = f'captured/envena_detect_arpspoof_{now}.pcap'
    try:
        filename = f'captured/envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except FileNotFoundError:
        filename = f'envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    arpspoof_packets = sniff(prn=lambda pkt: detect_arpspoof_in_package(packet=pkt, logger=logger), store=True, iface=param.iface)
    pcap_writer.write(arpspoof_packets)
    logger.info(f'Traffic was writted in "{filename}"')
 

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"ARP-spoofing atack detect module")
    parser.add_argument("-i", "--iface", help="network iface to sniff from", required=False, default=str(conf.iface))

    cli_args = parser.parse_args()
    args = Arguments()
    
    args.iface = cli_args.iface
    get_if_hwaddr(args.iface)
    
    t_detect_arpspoof = Tool(tool_func=detect_arpspoof, VERSION=1.0, args=args)
    
    t_detect_arpspoof.start_tool()
