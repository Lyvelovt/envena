from src.modules.ethernet.ip import IPProtocol

class UDPProtocol(IPProtocol):
    __slots__ = ('iface','count','timeout','send_func',
                             'ip_src','ip_dst','eth_src','eth_dst',
                             'port_src','port_dst')
    
    def __init__(self, iface, count, timeout, ip_src, \
        ip_dst, eth_src, eth_dst, send_func, port_src, port_dst):
        
        super().__init__(iface, count, timeout, send_func, ip_src, ip_dst, eth_src, eth_dst)
        
        if isinstance(port_src, int) and 0 <= port_src <= 65535:
            self.port_src = port_src
        else:
            raise ValueError('invalid port_src port got')
        
        if isinstance(port_dst, int) and 0 <= port_dst <= 65535:
            self.port_dst = port_dst
        else:
            raise ValueError('invalid port_dst port got')
        
        