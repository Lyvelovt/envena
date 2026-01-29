import enum
import ipaddress
from random import randint

from src.envena.core.protocols.ethernet.ip.udp import UDPProtocol
from src.envena.utils.validators import validate_ip

from .ack import send_dhcp_ack
from .discover import send_dhcp_discover
from .inform import send_dhcp_inform
from .nak import send_dhcp_nak
from .offer import send_dhcp_offer
from .release import send_dhcp_release
from .request import send_dhcp_request


class DHCPPacketType(enum.Enum):
    ACK = (1, send_dhcp_ack)
    DISCOVER = (2, send_dhcp_discover)
    INFORM = (1, send_dhcp_inform)
    NAK = (1, send_dhcp_nak)
    OFFER = (1, send_dhcp_offer)
    RELEASE = (1, send_dhcp_release)
    REQUEST = (1, send_dhcp_request)


class DHCPPacket(UDPProtocol):
    __slots__ = (
        "iface",
        "count",
        "timeout",
        "send_func",
        "ip_src",
        "ip_dst",
        "eth_src",
        "eth_dst",
        "packet_type",
        "xid",
        "hostname",
        "lease_time",
        "sub_mask",
        "dns_server",
        "port_src",
        "port_dst",
        "param_req_list",
        "logger",
    )

    def _get_send_func_by_type(self, packet_type: DHCPPacketType):
        return packet_type.value[1]

    def __init__(
        self,
        iface,
        count,
        timeout,
        ip_src,
        ip_dst,
        eth_src,
        eth_dst,
        packet_type,
        port_src=67,
        port_dst=68,
        lease_time=360,
        xid=randint(1_000_000, 9_999_999),
        hostname="",
        param_req_list: list = [1, 3, 15, 6],
        sub_mask=ipaddress.ip_address("255.255.255.0"),
        ip_router=None,
        dns_server="8.8.8.8",
        ttl=128,
    ):
        self.packet_type = packet_type

        send_func = self.send_func

        super().__init__(
            iface=iface,
            count=count,
            timeout=timeout,
            ip_src=ip_src,
            ip_dst=ip_dst,
            eth_src=eth_src,
            eth_dst=eth_dst,
            send_func=send_func,
            port_src=port_src,
            port_dst=port_dst,
            ttl=ttl,
        )

        if validate_ip(sub_mask):
            self.sub_mask = ipaddress.ip_address(sub_mask)
        else:
            raise TypeError("invalid subnet mask got")

        if isinstance(lease_time, int):  # and 0 <= lease_time <= 0xff_ff_ff_ff:
            self.lease_time = lease_time
        else:
            raise TypeError("invalid lease time got")

        if isinstance(xid, int):  # and 0 <= xid <= 0xff_ff_ff_ff:
            self.xid = xid
        else:
            raise TypeError("invalid XID got")

        if isinstance(hostname, str):  # and len(hostname) <= 255:
            self.hostname = hostname
        else:
            raise TypeError("invalid hostname got")

        if isinstance(param_req_list, list):
            self.param_req_list = param_req_list
        else:
            raise TypeError("invalid parameter request list got")

        if ip_router == None:
            self.ip_router = self.ip_src
        elif validate_ip(ip_router):
            self.ip_router = ipaddress.ip_address(ip_router)
        else:
            raise TypeError("invalid ip_router IP address got")

        if validate_ip(dns_server):
            self.dns_server = ipaddress.ip_address(dns_server)
        else:
            raise TypeError("invalid dns_server IP address got")

    def __setattr__(self, name, value):
        if name == "packet_type":
            if not isinstance(value, DHCPPacketType):
                raise TypeError("invalid packet type got")

            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, "send_func", send_func)
        object.__setattr__(self, name, value)
