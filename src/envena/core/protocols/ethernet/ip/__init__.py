import ipaddress
from typing import Annotated, Any, Union

from pydantic import Field, BeforeValidator
from src.envena.core.protocols.ethernet import EthernetProtocol
from src.envena.utils.validators import get_validated_ip

IpAddress = Annotated[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], BeforeValidator(get_validated_ip)]

class IPProtocol(EthernetProtocol):
    ip_src: IpAddress
    ip_dst: IpAddress
    ttl: int = Field(default=64, ge=1, le=255)

    # def __init__(
    #     self, 
    #     iface: str, 
    #     count: Union[int, float], 
    #     timeout: float, 
    #     send_func: Any, 
    #     ip_src: Any, 
    #     ip_dst: Any, 
    #     eth_src: Any, 
    #     eth_dst: Any, 
    #     ttl: int
    # ):
    #     super().__init__(
    #         iface=iface,
    #         send_func=send_func,
    #         count=count,
    #         timeout=timeout,
    #         eth_src=eth_src,
    #         eth_dst=eth_dst,
    #         ip_src=ip_src,
    #         ip_dst=ip_dst,
    #         ttl=ttl
    #     )