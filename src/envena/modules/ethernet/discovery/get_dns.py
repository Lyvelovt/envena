from src.envena.core.basetool import BaseTool
from src.envena.utils.network import get_hostname
from src.envena.core.arguments import public_args
from scapy.all import conf

# TODO: add store to workspace

dns_getHostname_v = 1.0


def get_dns(param, logger, ws) -> None:
    logger.info(f'DNS response: {param.input} is "{get_hostname(ip=param.input, iface=param.iface, dns_server=str(param.dns_server))}"')


class t_get_dns(BaseTool):
    """
    Reverse DNS lookup to find hostname by IP.

    Arguments:
        input (Required): Target IP address.

    Example:
        args set input 192.168.1.50
        dns_getHostname
    """

    def __init__(self, tool_func=get_dns, VERSION=1.1):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    # try:
    import time

    start_time = time.time()

    import argparse

    parser = argparse.ArgumentParser(
        description="Script witch get host domain name by IP-address",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-ip", help="target IP address", required=True, type=str)
    parser.add_argument( "-i", "--iface", help="network interface to send request from", default=str(conf.iface))
    parser.add_argument(
        "-ds", "--dns_server", help="DNS server to send request", required=False, type=str, default="8.8.8.8") 

    cli_args = parser.parse_args()
    public_args.input = cli_args.ip
    public_args.dns_server = cli_args.dns_server
    public_args.iface = cli_args.iface
    # get_dns(args)
    t_get_dns().start_tool()

# except KeyboardInterrupt:
# print("Aborted.")
# exit(0)
