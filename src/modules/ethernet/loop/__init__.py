import enum
from src.modules.ethernet import EthernetProtocol
from .loop import send_loop

class EthernetPacketType(enum.Enum):
    LOOP = (1, send_loop)

class LOOPPacket(EthernetProtocol):
    def _get_send_func_by_type(self, packet_type: EthernetPacketType):
        return packet_type.value[1]
    
    __slots__ = ('iface','count','timeout','send_func',
                             'ip_src','ip_dst','eth_src','eth_dst','packet_type', 'payload')
     
    def __init__(self, iface, count, timeout, \
        ip_src, ip_dst, eth_src, eth_dst, packet_type, payload=''):
        
        self.packet_type = packet_type
        
        send_func = self.send_func

        super().__init__(iface, count, timeout, ip_src, \
            ip_dst, eth_src, eth_dst, send_func)
        
        if isinstance(payload, str):
            self.payload = payload
        
    
    def __setattr__(self, name, value):
        if name == 'packet_type':
            if not isinstance(value, EthernetPacketType):
                raise TypeError('invalid packet type got')
            
            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, 'send_func', send_func)
        object.__setattr__(self, name, value)