import enum
from src.modules.ethernet.ip import IPProtocol
from .request import send_arp_request
from .response import send_arp_response

class ARPPacketType(enum.Enum):
    REQUEST = (1, send_arp_request)
    RESPONSE = (2, send_arp_response)

class ARPPacket(IPProtocol):
    def _get_send_func_by_type(self, packet_type: ARPPacketType):
        return packet_type.value[1]
    
    __slots__ = ('iface','count','timeout','send_func',
                             'ip_src','ip_dst','eth_src','eth_dst', 'packet_type', 'logger')
     
    def __init__(self, iface, count, timeout, \
        ip_src, ip_dst, eth_src, eth_dst, packet_type):
        
        self.packet_type = packet_type
        
        send_func = self.send_func
        
        super().__init__(iface, count, timeout, send_func,
            ip_src, ip_dst, eth_src, eth_dst, port_src=0, port_dst=0)
        
    
    def __setattr__(self, name, value):
        if name == 'packet_type':
            if not isinstance(value, ARPPacketType):
                raise TypeError('invalid packet type got')
            
            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, 'send_func', send_func)
        object.__setattr__(self, name, value)