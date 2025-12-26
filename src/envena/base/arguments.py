from src.envena.functions import validate_eth, validate_ip, parse_submask
import netaddr
import ipaddress
import logging
from math import inf
from src.envena.config import ROOT_LOGGER_NAME
from scapy.all import get_if_list, conf, get_if_addr, get_if_hwaddr

class NotSet:
    """Special type for not set args"""
    def __repr__(self):
        return "not set"
    
    def __str__(self):
        return "not set"

    def __bool__(self):
        return False
    
    def __int__(self):
        return 0
    
    def __float__(self):
        return 0.0


NOT_SET = NotSet()

class Arguments:
    __slots__ = ('ip_dst','ip_src','eth_dst','eth_src',
                  'iface','count','timeout','port_dst','port_src',
                  'sub_mask','sub_ip','xid','dns_server', 'input','logger',
                  'hw_dst', 'hw_src', 'bssid', 'ssid')
    
    def __init__(self):
        for name in self.__slots__:
            object.__setattr__(self, name, NOT_SET)
            
        logger_name = f"{ROOT_LOGGER_NAME}.{self.__class__.__name__}"
        # self.logger = logging.getLogger(logger_name)
        logger_instance = logging.getLogger(logger_name)
        object.__setattr__(self, 'logger', logger_instance)
        
        # Values as default
        self.iface = str(conf.iface)
        self.eth_src = get_if_hwaddr(self.iface)
        self.ip_src = get_if_addr(self.iface)
        self.dns_server = ipaddress.ip_address('8.8.8.8')
        self.count = 1
        self.hw_src = self.eth_src
        # self.sub_mask = parse_submask(sub_mask='24')
        # self.sub_ip = ipaddress.ip_address('.'.join(str(self.ip_src).split('.').pop().append('0')))
        
        
        
    def __setattr__(self, name, value):
        if name == 'logger':
            # Разрешаем присвоение логгера (если кто-то вызывает его явно)
            object.__setattr__(self, name, value)
            return
        
        if name in ['ip_dst', 'ip_src', 'sub_ip', 'dns_server']:
            if validate_ip(value):
                object.__setattr__(self, name, ipaddress.ip_address(value))
                return
            else:
                raise ValueError(f'Invalid value "{value}" for "{name}"')
            
        elif name in ['eth_dst', 'eth_src', 'hw_dst', 'hw_src', 'bssid']:
            if validate_eth(value):
                object.__setattr__(self, name, netaddr.EUI(value))
                return
            else:
                raise ValueError(f'Invalid value "{value}" for "{name}"')
            
        elif name in ['port_src', 'port_dst']:
            if not isinstance(value, int):
                raise TypeError(f'Invalid value "{value}" for "{name}"')
            elif not 0 <= value <= 65535:
                raise ValueError(f'Invalid value "{value}" for "{name}"')
            else:
                object.__setattr__(self, name,  value)
                return
            
        elif name == 'count':
            if not (isinstance(value, int) or value == inf):
                raise TypeError(f'Invalid value "{value}" for "{name}"')
            else:
                object.__setattr__(self, name, value)
                return
            
        elif name == 'timeout':
            if not (isinstance(value, float) or isinstance(value, int)):
                raise TypeError(f'Invalid value "{value}" for "{name}"')
            else:
                object.__setattr__(self, name, value)
                return
            
        elif name == 'iface':
            if not isinstance(value, str):
                raise TypeError(f'Invalid value "{value}" for "{name}"')
            elif not value in get_if_list():
                raise ValueError(f'Invalid value "{value}" for "{name}"')
            else:
                object.__setattr__(self, name, value)
                return
            
        elif name == 'sub_mask':
            if parse_submask(value):
                object.__setattr__(self, name, parse_submask(value))
                return
            else:
                raise ValueError(f'Invalid value "{value}" for "{name}"')
            
        elif name == 'xid':
            if isinstance(value, int):
                object.__setattr__(self, name, value)
                return
            else:
                raise TypeError(f'Invalid value "{value}" for "{name}"')
        elif name == 'ssid':
            if not isinstance(value, str):
                raise TypeError(f'Invalid type "{type(value)}" for {name}')
            elif len(value) < 32:
                raise ValueError(f'{name} cannot be longer than 32 letters')
            else:
                object.__setattr__(self, name, value)
        elif name == 'input':
            if isinstance(value, str):
                object.__setattr__(self, name, value)
                return
            else:
                raise TypeError(f'Invalid value "{value}" for "{name}"')
            
        else:
                raise AttributeError(f'Invalid argument "{name}"')

public_args = Arguments()