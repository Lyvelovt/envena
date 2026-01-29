from src.envena.core.basetool import BaseTool
from src.envena.modules.ethernet.utils import CATEGORY_DOC
from src.envena.utils.network import get_hostname

# TODO: complete this module

dns_getHostname_v = 1.0


def dns_getHostname(param, logger, ws) -> None:
    logger.info(f'DNS response: {param.input} is "{get_hostname(ip=param.input, iface=param.iface, dns_server=str(param.dns_server))}"')


class t_dns_getHostname(BaseTool):
    """
    Reverse DNS lookup to find hostname by IP.

    Arguments:
        input (Required): Target IP address.

    Example:
        args set input 192.168.1.50
        dns_getHostname
    """

    def __init__(self, tool_func=dns_getHostname, VERSION=1.0):
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
        "-ip", help="target IP.", required=True, type=str
    )  # , required=True)
    # parser.add_argument( "-i", "--interface", help="Network interface.")

    arg = parser.parse_args()
    args = {}
    args["input"] = arg.ip
    dns_getHostname(args)

# except KeyboardInterrupt:
# print("Aborted.")
# exit(0)
