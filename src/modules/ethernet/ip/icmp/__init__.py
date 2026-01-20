import enum
from src.modules.ethernet.ip import IPProtocol
from random import randint
import ipaddress
from src.envena.functions import validate_ip

from .echo_request import send_icmp_echo_request
from .echo_reply import send_icmp_echo_reply

class ICMPPacketType(enum.Enum):
    ECHO_REQUEST = (1, send_icmp_echo_request)
    ECHO_REPLY = (2, send_icmp_echo_reply)

class ICMPPacket(IPProtocol):
    __slots__ = ('iface','count','timeout','send_func',
                             'ip_src','ip_dst','eth_src','eth_dst','packet_type',
                             'seq','icmp_id','payload','logger')
    
    def _get_send_func_by_type(self, packet_type: ICMPPacketType):
        return packet_type.value[1]
    
    def __init__(self, iface, count, timeout, eth_src, eth_dst,
        ip_src, ip_dst, packet_type,
        seq, icmp_id, ttl, payload=''):
        
        self.packet_type = packet_type
        
        send_func = self.send_func

        super().__init__(iface=iface, count=count, timeout=timeout, 
                         send_func=send_func, ip_src=ip_src, 
                         ip_dst=ip_dst, eth_src=eth_src, eth_dst=eth_dst, ttl=ttl)
        
        if isinstance(seq, int) and 0 <= seq <= 65535:
            self.seq = seq
        else:
            raise TypeError('invalid seq got')
        
        if isinstance(icmp_id, int) and 0 <= icmp_id <= 65535:
            self.icmp_id = icmp_id
        else:
            raise TypeError('invalid id got')

        self.payload = str(payload)
            
    def __setattr__(self, name, value):
        if name == 'packet_type':
            if not isinstance(value, ICMPPacketType):
                raise TypeError('invalid packet type got')
            
            send_func = self._get_send_func_by_type(value)
            object.__setattr__(self, 'send_func', send_func)
        object.__setattr__(self, name, value)