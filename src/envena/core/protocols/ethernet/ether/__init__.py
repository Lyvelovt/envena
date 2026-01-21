import enum
from src.envena.core.protocols.ethernet import EthernetProtocol
from .ether import send_ether

class EtherPacketType(enum.Enum):
    Ether = (1, send_ether)

class EtherPacket(EthernetProtocol):
    def _get_send_func_by_type(self, packet_type: EtherPacketType):
        return packet_type.value[1]
    
    __slots__ = ('iface','count','timeout','send_func',
                             'eth_src','eth_dst','packet_type', 'payload', 'logger')
     
    def __init__(self, iface, count, timeout, \
        eth_src, eth_dst, packet_type, payload=''):
        
        self.packet_type = packet_type
        
        send_func = self.send_func

        super().__init__(iface=iface, send_func=send_func, count=count, timeout=timeout,
            eth_src=eth_src, eth_dst=eth_dst)
        
        if isinstance(payload, str):
            self.payload = payload
        
    
    def __setattr__(self, name, value):
        if name == 'packet_type':
            if not isinstance(value, EtherPacketType):
                raise TypeError('invalid packet type got')
            
            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, 'send_func', send_func)
        object.__setattr__(self, name, value)