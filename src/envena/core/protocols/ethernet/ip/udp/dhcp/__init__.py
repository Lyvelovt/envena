import enum
import ipaddress
from random import randint
from typing import Annotated, Any, List

from pydantic import BeforeValidator, Field, model_validator

from src.envena.core.protocols.ethernet.ip.udp import UDPProtocol
from src.envena.utils.validators import get_validated_ip

IpAddress = Annotated[ipaddress.IPv4Address, BeforeValidator(get_validated_ip)]


class DHCPPacketType(enum.Enum):
    ACK = (1, "send_dhcp_ack")  # Замени на импорты функций
    DISCOVER = (2, "send_dhcp_discover")
    INFORM = (1, "send_dhcp_inform")
    NAK = (1, "send_dhcp_nak")
    OFFER = (1, "send_dhcp_offer")
    RELEASE = (1, "send_dhcp_release")
    REQUEST = (1, "send_dhcp_request")


class DHCPPacket(UDPProtocol):
    packet_type: DHCPPacketType
    xid: int = Field(default_factory=lambda: randint(1_000_000, 9_999_999))
    hostname: str = ""
    lease_time: int = 360
    sub_mask: IpAddress = ipaddress.ip_address("255.255.255.0")
    ip_router: Any = None
    dns_server: IpAddress = ipaddress.ip_address("8.8.8.8")
    param_req_list: List[int] = [1, 3, 15, 6]

    @model_validator(mode="after")
    def set_dynamic_fields(self) -> "DHCPPacket":
        if self.ip_router is None:
            self.ip_router = self.ip_src
        else:
            self.ip_router = get_validated_ip(self.ip_router)

        # Установка send_func на основе типа пакета
        from .ack import send_dhcp_ack  # Предполагаемые импорты
        from .discover import send_dhcp_discover

        mapping = {
            DHCPPacketType.ACK: send_dhcp_ack,
            DHCPPacketType.DISCOVER: send_dhcp_discover,
            # ... остальные маппинги
        }
        self.send_func = mapping.get(self.packet_type)
        return self

    # def __init__(self, **data):
    # packet_type = data.get('packet_type')
    # super().__init__(**data)
