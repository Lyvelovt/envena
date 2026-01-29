import enum

from src.envena.core.protocols.baseprotocol import BaseProtocol
from src.envena.utils.functions import validate_eth

from .deauth import send_deauth


class Dot11PacketType(enum.Enum):
    DEAUTH = (1, send_deauth)


class Dot11Packet(BaseProtocol):
    def _get_send_func_by_type(self, packet_type: Dot11PacketType):
        return packet_type.value[1]

    __slots__ = (
        "iface",
        "count",
        "timeout",
        "send_func",
        "hw_src",
        "hw_dst",
        "bssid",
        "packet_type",
        "payload",
        "logger",
    )

    def __init__(
        self, iface, count, timeout, hw_src, hw_dst, bssid, packet_type, payload=""
    ):
        self.packet_type = packet_type

        self.hw_src = hw_src
        self.hw_dst = hw_dst
        self.bssid = bssid

        send_func = self.send_func

        super().__init__(iface=iface, count=count, timeout=timeout, send_func=send_func)

        if isinstance(payload, str):
            self.payload = payload

    def __setattr__(self, name, value):
        if name == "packet_type":
            if not isinstance(value, Dot11PacketType):
                raise TypeError("invalid packet type got")

            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, "send_func", send_func)
            object.__setattr__(self, name, value)

        elif name == "hw_src" or name == "hw_dst" or name == "bssid":
            if not validate_eth(value):
                raise ValueError(f"invalid value {value} for {name}")
            else:
                object.__setattr__(self, name, value)
