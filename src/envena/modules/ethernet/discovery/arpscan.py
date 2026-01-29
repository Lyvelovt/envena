import time
from random import shuffle, uniform

from scapy.all import ARP, AsyncSniffer, conf, get_if_addr, get_if_hwaddr

from src.envena.core.arguments import public_args
from src.envena.core.basetool import BaseTool
from src.envena.core.protocols.ethernet.ip.arp import ARPPacket, ARPPacketType
from src.envena.core.workspace import Workspaces
from src.envena.modules.ethernet.discovery import CATEGORY_DOC
from src.envena.utils.generators import get_vendor
from src.envena.utils.network import get_hostname
from src.envena.utils.parsers import parse_ip_ranges

arpscan_v = 2.1

from rich.console import Console
from rich.table import Table


def print_aligned_table(devices: list) -> None:
    if not devices:
        return

    console = Console()
    table = Table(show_header=True, header_style="bold cyan")

    table.add_column("IP", style="green", justify="left")
    table.add_column("Ethernet", style="magenta", justify="left")
    table.add_column("Hostname", style="yellow", justify="left")
    table.add_column("Vendor", style="blue", justify="left")

    for device in devices:
        hostname = device.get("hostname", "unknown")
        vendor = get_vendor(eth=device["eth"])
        if not vendor:
            vendor = "unknown"

        table.add_row(device["ip"], device["eth"], hostname, vendor)

    console.print(table)


def scan_network(
    logger,
    ip_range: str,
    ip_src: str = None,
    eth_src: str = None,
    iface: str = conf.iface,
    timeout: int = 4,
) -> list:
    devices = []
    answered = []
    # Filter out our own IP
    # self_ip = ip_src if ip_src else scapy.get_if_addr(iface)
    target_ips = [ip for ip in ip_range if ip != ip_src]
    shuffle(target_ips)

    # ARP sniff callback
    def arp_callback(pkt):
        if pkt[ARP].op == 2:  # is-at (response)
            answered.append(pkt)

    # Start sniffing in background
    timeout_coeff = timeout / len(target_ips)

    sniff_filter = "arp"
    sniffer = AsyncSniffer(iface=iface, prn=arp_callback, filter=sniff_filter, store=0)

    sniffer.start()

    for number, ip in enumerate(target_ips):
        ARPPacket(
            iface=iface,
            count=1,
            timeout=0,
            ip_src=ip_src,
            ip_dst=ip,
            eth_src=eth_src,
            eth_dst="ff:ff:ff:ff:ff:ff",
            packet_type=ARPPacketType.REQUEST,
        ).send_packet(verbose=False)
        # scapy.sendp(
        #         scapy.Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src) /
        #         scapy.ARP(pdst=ip,
        #                   psrc=ip_src,
        #                   hwsrc=eth_src),
        #         verbose=False, iface=iface)
        logger.info(f"[{number + 1}/{len(target_ips)}] Processing {ip}...")
        delay = timeout_coeff + uniform(-timeout_coeff / 3, timeout_coeff / 3)
        time.sleep(delay)
        # arp_request = scapy.ARP(pdst=ip, psrc=ip_src, hwsrc=eth_src)
        # print(arp_request)
    # broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.sendp(broadcast/arp_request, verbose=False)

    # Wait for responses
    # print(f'Scanning(1..{len(target_ips)})... \r', end='')
    # time.sleep(timeout)
    if sniffer.running:
        sniffer.stop()

    # Process responses
    for pkt in answered:
        ip = pkt[ARP].psrc
        eth = pkt[ARP].hwsrc
        hostname = get_hostname(ip)
        devices.append({"ip": ip, "eth": eth, "hostname": hostname})

    logger.info(f"Scanned ({len(target_ips)}/{len(target_ips)})")
    deduplicated_devices = [dict(t) for t in set(tuple(d.items()) for d in devices)]
    return deduplicated_devices


def arpscan(param, logger, ws=None) -> None:
    # try:
    iface = param.iface if param.iface else str(conf.iface)
    eth_src = get_if_hwaddr(iface)
    ip_src = get_if_addr(iface)
    start_time = time.time()
    # if not param.input:
    # raise AttributeError(f"IP range input is required")

    try:
        ip_range = parse_ip_ranges(param.input)
    except ValueError:
        logger.fatal("Invalid IP-address(es) got")
        return
    if len(ip_range) == 0:
        logger.fatal("Invalid IP-address(es) got")
        return

    devices_info = scan_network(
        logger=logger,
        ip_range=ip_range,
        eth_src=eth_src,
        ip_src=ip_src,
        iface=iface,
        timeout=param.timeout if param.timeout else 7,
    )

    if devices_info:
        logger.info(f"Scan finished in {round(time.time() - start_time, 3)} s.")
        logger.info(f"Detected {len(devices_info)}/{len(ip_range)} device(s)")
        print_aligned_table(devices_info)
        if ws and ws.current:
            for device in devices_info:
                ws.set_host(
                    mac=device["eth"],
                    ip=device["ip"],
                    vendor=get_vendor(device["eth"]),
                    hostname=device["hostname"],
                )

    else:
        logger.info("Failed to detect device(s) on the network")


# except KeyboardInterrupt:
#     logger.info(f"Scan finished in {round(time.time() - start_time, 3)} s.")


class t_arpscan(BaseTool):
    """
    Network discovery using ARP requests.

    Arguments:
        input (Required): Target subnet or IP (e.g. 192.168.1.0/24).
        timeout (Optional): Waiting time for responses (default: 10).
        iface (Optional): Interface to scan from.

    Example:
        args set input 192.168.1.0/24
        arpscan
    """

    def __init__(self, tool_func=arpscan, VERSION=2.2):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ARPscan is a scanner that use ARP protocol"
    )
    parser.add_argument("-ip", help="target IP or range", required=True, type=str)
    parser.add_argument(
        "-t",
        "--timeout",
        help="waiting time for responses in seconds",
        required=False,
        type=float,
        default=10,
    )
    parser.add_argument(
        "-i",
        "--iface",
        help="interface to scanning from",
        required=False,
        default=str(conf.iface),
    )
    # parser.add_argument("-i", "--iface", help="interface to scanning from", required=False, default=str(conf.)
    cli_args = parser.parse_args()
    # args = Arguments()
    public_args.iface = cli_args.iface
    public_args.input = cli_args.ip
    public_args.timeout = cli_args.timeout

    t_arpscan().start_tool()
