import enum
from typing import Any

from pydantic import Field, model_validator

from src.envena.core.protocols.ethernet.ip import IPProtocol


class ICMPPacketType(enum.Enum):
    ECHO_REQUEST = (1, "send_icmp_echo_request")
    ECHO_REPLY = (2, "send_icmp_echo_reply")


class ICMPPacket(IPProtocol):
    packet_type: ICMPPacketType
    seq: int = Field(ge=0, le=65535)
    icmp_id: int = Field(ge=0, le=65535)
    payload: str = ""

    @model_validator(mode="after")
    def set_send_func(self) -> "ICMPPacket":
        from .echo_reply import send_icmp_echo_reply
        from .echo_request import send_icmp_echo_request

        mapping = {
            ICMPPacketType.ECHO_REQUEST: send_icmp_echo_request,
            ICMPPacketType.ECHO_REPLY: send_icmp_echo_reply,
        }
        self.send_func = mapping.get(self.packet_type)
        return self

    # def __init__(self, **data):
    #     packet_type = data.get('packet_type')
    #     super().__init__(**data)
