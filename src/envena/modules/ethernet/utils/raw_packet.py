from scapy.all import conf, hexdump, sendp

from src.envena.core.arguments import Arguments, public_args
from src.envena.core.basetool import BaseTool
from src.envena.modules.ethernet.utils import CATEGORY_DOC


def send_raw_packet(param, logger, verbose: bool = True, ws=None) -> bool:
    try:
        with open(param.input, "r") as pkt_file:
            dump = pkt_file.read()
            dump = bytes.fromhex(dump)
    except FileNotFoundError:
        logger.critical("Invalid filename input got")
        return
    try:
        sendp(dump, verbose=False, iface=param.iface)
        if verbose:
            hexdump(dump)
        return True
    except Exception as e:
        logger.error(f"Packet was not sent: {e}")
        return False


class t_raw_packet(BaseTool):
    """
    Transmit raw bytes from a hex-stream file.

    Arguments:
        input (Required): Path to file with hex-string (e.g. ./pkt.hex).
        iface (Optional): Interface to transmit from.

    Example:
        args set input my_packet.hex
        raw_packet
    """

    def __init__(self, tool_func=send_raw_packet, VERSION=1.1):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Raw packet send script")
    parser.add_argument(
        "-i",
        "--iface",
        help="network interface to send from",
        required=False,
        default=str(conf.iface),
        type=str,
    )
    parser.add_argument(
        "-f", "--file", help="the hexstream file to send", required=True, type=str
    )

    cli_args = parser.parse_args()

    args = Arguments()

    public_args.input = cli_args.file
    public_args.iface = cli_args.iface

    t_raw_packet().start_tool()
