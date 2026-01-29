import netaddr
import ipaddress
from netaddr.core import AddrFormatError, NotRegisteredError
from scapy.arch.common import compile_filter
from scapy.error import Scapy_Exception


def get_validated_eth(v: any) -> netaddr.EUI:
    '''
    Return validated EUI type MAC address.
    
    Args:
        v (str | netaddr.EUI): Input MAC address.
    
    Returns:
        netaddr.EUI: EUI address object (validated MAC address).
    
    Raises:
        ValueError: If input address format total incorrect and cannot be returned into MAC address.
    '''
    if isinstance(v, netaddr.EUI):
        return v
    str_v = str(v)
    if not validate_eth(str_v):
        raise ValueError(f"Invalid ETH/MAC address: {v}")
    return netaddr.EUI(str_v)

def get_validated_ip(v: any) -> ipaddress.IPv4Address:
    '''
    Return validated IPv4Address type MAC address.
    
    Args:
        v (str | ipaddress.IPv4Address): Input IP address.
    
    Returns:
        ipaddress.IPv4Address: IPv4 address object (validated IP address).
    
    Raises:
        ValueError: If input address format total incorrect and cannot be returned into IP address.
    '''
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return v
    str_v = str(v)
    if not validate_ip(str_v):
        raise ValueError(f"Invalid IP address: {v}")
    return ipaddress.ip_address(str_v)



### TODO: Replace this to classic netaddr and ipaddress validations
# Validate IP-address
def validate_ip(ip: str = "") -> bool:
    """
    Will been replaced soon !
    """
    try:
        ip = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

### This too
# Validate eth-address
def validate_eth(eth: str = "", is_oui: bool = False) -> bool:
    """
    Will be replaced soon !
    """
    try:
        if is_oui:
            eth = netaddr.OUI(eth)
        else:
            eth = netaddr.EUI(eth)
        return True
    except (AddrFormatError, TypeError, ValueError):
        return False
### END OF TODO

# Validate BPF string
def validate_bpf(filter: str, iface=None) -> bool:
    """
    Validate BPF using scapy (libpcap). Check whether, if string is correct BPF.
    
    Args:
        filter (str): Input BPF string.
        iface (str | optional): Iface to parse BPF in.
        
    Returns:
        answer (bool): Input string is correct BPF?
    """
    try:
        compile_filter(filter, iface)
        return True
    except Scapy_Exception:
        return False