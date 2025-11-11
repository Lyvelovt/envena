import enum
import ipaddress
from typing import Union, Optional

class IPaddrType(enum.Enum):
    PRIVATE = enum.auto()       # 192.168.x.x, 10.x.x.x, 172.16.x.x
    MULTICAST = enum.auto()     # 224.x.x.x - 239.x.x.x
    GLOBAL = enum.auto()        # Routing in Internet
    RESERVED = enum.auto()      # 240.x.x.x/4
    LOOPBACK = enum.auto()      # 127.x.x.x/8
    LINK_LOCAL = enum.auto()    # 169.254.x.x/16
    UNSPECIFIED = enum.auto()   # 0.0.0.0
    
    @staticmethod
    def get_type(ipaddr: Union[str, ipaddress.IPv4Address]) -> Optional['IPaddrType']:
        try:
            if isinstance(ipaddr, str):
                ip_obj = ipaddress.ip_address(ipaddr)
            else:
                ip_obj = ipaddr

            if ip_obj.is_unspecified:
                return IPaddrType.UNSPECIFIED
            
            if ip_obj.is_loopback:
                return IPaddrType.LOOPBACK
            
            if ip_obj.is_link_local:
                return IPaddrType.LINK_LOCAL
            
            if ip_obj.is_multicast:
                return IPaddrType.MULTICAST
            
            if ip_obj.is_private:
                return IPaddrType.PRIVATE

            if ip_obj.is_reserved:
                return IPaddrType.RESERVED
            
            if ip_obj.is_global:
                return IPaddrType.GLOBAL
                
            return None 

        except ValueError:
            return None