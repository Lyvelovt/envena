import netaddr
from pydantic import field_validator, BeforeValidator
from typing import Annotated, Any

from src.envena.core.protocols.baseprotocol import BaseProtocol
from src.envena.utils.validators import get_validated_eth


MacAddress = Annotated[netaddr.EUI, BeforeValidator(get_validated_eth)]

class EthernetProtocol(BaseProtocol):
    eth_src: MacAddress
    eth_dst: MacAddress

    # def __init__(self, iface, count, timeout, send_func, eth_src, eth_dst):
    #     super().__init__(
    #         iface=iface, 
    #         count=count, 
    #         timeout=timeout, 
    #         send_func=send_func, 
    #         eth_src=eth_src, 
    #         eth_dst=eth_dst
    #     )