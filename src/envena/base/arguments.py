from src.envena.functions import validate_eth, validate_ip, parse_submask
import netaddr
import ipaddress
import logging
from math import inf
from src.envena.config import ROOT_LOGGER_NAME
from scapy.all import get_if_list

class Arguments:
    __slots__ = ('ip_dst','ip_src','eth_dst','eth_src',
                  'iface','count','timeout','port_dst','port_src',
                  'sub_mask','sub_ip','xid','dns_server', 'input','logger')
    
    def __init__(self):
        for name in self.__slots__:
            object.__setattr__(self, name, None)
            
        logger_name = f"{ROOT_LOGGER_NAME}.{self.__class__.__name__}"
        # self.logger = logging.getLogger(logger_name)
        logger_instance = logging.getLogger(logger_name)
        object.__setattr__(self, 'logger', logger_instance)
        
    def __setattr__(self, name, value):
        if name == 'logger':
            # Разрешаем присвоение логгера (если кто-то вызывает его явно)
            object.__setattr__(self, name, value)
            return
        
        if name == 'ip_dst':
            if validate_ip(value):
                object.__setattr__(self, name, ipaddress.ip_address(value))
                return
            else:
                self.logger.error('Invalid IP-address got')
        elif name == 'ip_src':
            if validate_ip(value):
                object.__setattr__(self, name,ipaddress.ip_address(value))
                return
            else:
                self.logger.error('Invalid IP-address got')
        elif name == 'eth_dst':
            if validate_eth(value):
                object.__setattr__(self, name, netaddr.EUI(value))
                return
            else:
                self.logger.error('Invalid MAC-address got')
        elif name == 'eth_src':
            if validate_eth(value):
                object.__setattr__(self, name, netaddr.EUI(value))
                return
            else:
                self.logger.error('Invalid MAC-address got')
        elif name == 'port_src':
            if isinstance(value, int) and 0 <= value <= 65535:
                object.__setattr__(self, name,  value)
                return
            else:
                self.logger.error('Invalid port got')
        elif name == 'port_dst':
            if isinstance(value, int) and 0 <= value <= 65535:
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid port got')
        elif name == 'count':
            if isinstance(value, int) or value == inf:
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid count got')
        elif name == 'timeout':
            if isinstance(value, float) or isinstance(value, int):
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid timeout got')
        elif name == 'iface':
            if isinstance(value, str) and value in get_if_list():
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid interface got')
        elif name == 'sub_mask':
            if parse_submask(value):
                object.__setattr__(self, name, parse_submask(value))
                return
            else:
                self.logger.error('Invalid IP-address got')
        elif name == 'sub_ip':
            if validate_ip(value):
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid IP-address got')
        elif name == 'xid':
            if isinstance(value, int):
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid XID got')
        elif name == 'dns_server':
            if validate_ip(value):
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('Invalid IP-address got')
        elif name == 'input':
            if isinstance(value, str):
                object.__setattr__(self, name, value)
                return
            else:
                self.logger.error('nvalid input got')
        else:
                self.logger.error('Invalid argument got')