from pydantic import Field

from src.envena.core.protocols.ethernet.ip import IPProtocol


class UDPProtocol(IPProtocol):
    port_src: int = Field(default=0, ge=0, le=65535)
    port_dst: int = Field(default=0, ge=0, le=65535)

    # def __init__(self, **data):
    # super().__init__(**data)
