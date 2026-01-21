from src.envena.core.protocols.ethernet.ip import IPProtocol

class UDPProtocol(IPProtocol):
    __slots__ = ('iface','count','timeout','send_func',
                             'ip_src','ip_dst','eth_src','eth_dst',
                             'port_src','port_dst','ttl')
    
    def __init__(self, iface, count, timeout, send_func, eth_src, eth_dst, ip_src,
        ip_dst, port_src, port_dst, ttl=128):
        
        super().__init__(iface=iface, count=count, timeout=timeout, 
                         send_func=send_func, ip_src=ip_src, ip_dst=ip_dst, 
                         eth_src=eth_src, eth_dst=eth_dst, ttl=ttl)
        
        if isinstance(port_src, int) and 0 <= port_src <= 65535:
            self.port_src = port_src
        else:
            raise ValueError('invalid port_src port got')
        
        if isinstance(port_dst, int) and 0 <= port_dst <= 65535:
            self.port_dst = port_dst
        else:
            raise ValueError('invalid port_dst port got')
        
        