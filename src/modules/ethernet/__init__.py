from src.envena.base.protocol import BaseProtocol
from src.envena.functions import validate_eth
import netaddr

class EthernetProtocol(BaseProtocol):
    __slots__ = ('iface','count','timeout','send_func',
                             'eth_src','eth_dst')
    
    def __init__(self, iface, count, timeout, send_func, eth_src, eth_dst):
        
        super().__init__(iface, count, timeout, send_func)
        
        if validate_eth(eth_src):
            self.eth_src = netaddr.EUI(eth_src)
        else:
            raise ValueError('invalid eth_src MAC address got')
        if validate_eth(eth_dst):
            self.eth_dst = netaddr.EUI(eth_dst)
        else:
            raise ValueError('invalid eth_dst MAC address got')