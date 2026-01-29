import ipaddress

from src.envena.core.protocols.ethernet import EthernetProtocol
from src.envena.utils.validators import validate_ip


class IPProtocol(EthernetProtocol):
    __slots__ = (
        "iface",
        "count",
        "timeout",
        "send_func",
        "ip_src",
        "ip_dst",
        "eth_src",
        "eth_dst",
        "ttl",
    )

    def __init__(
        self, iface, count, timeout, send_func, ip_src, ip_dst, eth_src, eth_dst, ttl
    ):
        super().__init__(
            iface=iface,
            send_func=send_func,
            count=count,
            timeout=timeout,
            eth_src=eth_src,
            eth_dst=eth_dst,
        )

        if validate_ip(ip_src):
            self.ip_src = ipaddress.ip_address(ip_src)
        else:
            raise ValueError(f"invalid ip_src {ip_src} IP-address got")
        if validate_ip(ip_dst):
            self.ip_dst = ipaddress.ip_address(ip_dst)
        else:
            raise ValueError(f"invalid ip_dst {ip_dst} IP-address got")

        # if isinstance(port_src, int) and 0 <= port_src <= 65535:
        #     self.port_src = port_src
        # else:
        #     raise ValueError('invalid port_src port got')

        # if isinstance(port_dst, int) and 0 <= port_dst <= 65535:
        #     self.port_dst = port_dst
        # else:
        #     raise ValueError('invalid port_dst port got')

        if isinstance(ttl, int) and 1 <= ttl <= 255:
            self.ttl = ttl
        else:
            raise ValueError("invlaid TTL got")
