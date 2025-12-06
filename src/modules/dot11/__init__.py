import enum
from src.envena.base.protocol import BaseProtocol
from .deauth import send_deauth
from src.envena.functions import validate_eth

class Dot11PacketType(enum.Enum):
    Deauth = (1, send_deauth)

class Dot11Packet(BaseProtocol):
    def _get_send_func_by_type(self, packet_type: Dot11PacketType):
        return packet_type.value[1]
    
    __slots__ = ('iface','count','timeout','send_func',
                             'hw_src','hw_dst','packet_type', 'payload', 'logger')
     
    def __init__(self, iface, count, timeout, \
        hw_src, hw_dst, packet_type, payload=''):
        
        self.packet_type = packet_type
        
        send_func = self.send_func

        super().__init__(iface, count, timeout,
            send_func, eth_src, eth_dst)
        
        if isinstance(payload, str):
            self.payload = payload
        
        
    
    def __setattr__(self, name, value):
        if name == 'packet_type':
            if not isinstance(value, EtherPacketType):
                raise TypeError('invalid packet type got')
            
            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, 'send_func', send_func)
        object.__setattr__(self, name, value)
        
        elif name == 'hw_src' or name == 'hw_dst':
            if not validate_eth(value):
                raise ValueError(f'invalid value {value} for {name}')