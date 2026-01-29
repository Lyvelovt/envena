from pydantic import Field

from src.envena.core.protocols.ethernet.ip import IPProtocol


class TCPProtocol(IPProtocol):
    port_src: int = Field(ge=0, le=65535)
    port_dst: int = Field(ge=0, le=65535)

    # def __init__(self, **data):
    # super().__init__(**data)
