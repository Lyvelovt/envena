import enum

from pydantic import model_validator

from src.envena.core.protocols.ethernet.ip import IPProtocol


class ARPPacketType(enum.Enum):
    REQUEST = (1, "send_arp_request")
    RESPONSE = (2, "send_arp_response")


class ARPPacket(IPProtocol):
    packet_type: ARPPacketType
    ttl: int = 128

    @model_validator(mode="after")
    def set_send_func(self) -> "ARPPacket":
        from .request import send_arp_request
        from .response import send_arp_response

        mapping = {
            ARPPacketType.REQUEST: send_arp_request,
            ARPPacketType.RESPONSE: send_arp_response,
        }
        self.send_func = mapping.get(self.packet_type)
        return self

    # def __init__(self, **data):
    #     if 'ttl' not in data:
    #         data['ttl'] = 128
    #     packet_type = data.get('packet_type')
    #     super().__init__(**data)
