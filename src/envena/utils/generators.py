import ipaddress
import random
import string
from random import randint

import netaddr
from netaddr import NotRegisteredError


# Brute force attack to XID (for now unuseful shit)
def ex_search_xid(from_begin: bool = True) -> any:
    if from_begin:
        xid = 1000000
    for xid in range(1000000, 9999999):
        yield xid


def get_sub_ip(host_ip: str = "0.0.0.0", mask: str = "255.255.255.0") -> str:
    """
    Get subnet IP address from host IP and subnet mask.

    Args:
        host_ip (str): IP address of any host from current subnet.
        mask (str): subnet mask of current subnet.

    Returns:
        network (str): IP address of subnet.
    """
    if host_ip == "0.0.0.0":
        return "0.0.0.0"
    network_cidr_str = f"{host_ip}/{mask}"
    network_obj = ipaddress.ip_network(network_cidr_str, strict=False)

    return str(network_obj.network_address)


def get_ip_broadcast(host_ip: str = "0.0.0.0", mask: str = "255.255.255.0") -> str:
    """
    Get broadcast IP of subnet.

    Args:
        host_ip (str): IP address of any host from current subnet.
        mask (str): subnet mask of current subnet.

    Returns:
        network (str): Broadcast IP address of subnet.
    """
    if host_ip == "0.0.0.0":
        return "0.0.0.0"
    network_cidr_str = f"{host_ip}/{mask}"
    network_obj = ipaddress.ip_network(network_cidr_str, strict=False)

    return str(network_obj.broadcast_address)


# Get manufacturer's company by OUI of EUI address
def get_vendor(eth: str = "") -> str | None:
    """
    Get network interface vendor by OUI (first 6 bytes of MAC address).

    Args:
        eth (str): Target MAC address.

    Returns:
        vendor (str | None): Vendor name if it exists in OUI database, else None.
    """
    eth = netaddr.EUI(eth)
    try:
        return eth.oui.registration().org
    except NotRegisteredError:
        return None


# Return random IP-address by mask or not
def rand_ip(mask: str = "x.x.x.x") -> str:
    """
    Generate random IP address by mask or not. Replase all 'x' to random bytes.

    Args:
        mask (str | "x.x.x.x"): Input mask. 'x' will be replased to random bytes. Example "192.168.1.x"

    Returns:
        ip (str): randomized IP address by mask.

    Raises:
        ValueError: Incorrect format of mask.
    """
    try:
        mask = mask.split(".")
    except ValueError:
        raise ValueError("Incorrect format of IP generator mask")
    return f"{str(randint(0, 255)) if mask[0] == 'x' else mask[0]}.{str(randint(0, 255)) if mask[1] == 'x' else mask[1]}.{str(randint(0, 255)) if mask[2] == 'x' else mask[2]}.{str(randint(0, 255)) if mask[3] == 'x' else mask[3]}"


# Return random eth-address by mask or not
def rand_eth(mask: str = "x:x:x:x:x:x") -> str:
    """
    Generate random MAC address by mask or not. Replase all 'x' to random bytes.

    Args:
        mask (str | "x.x.x.x"): Input mask. 'x' will be replased to random bytes. Example "x:01:00:02:ff:x".

    Returns:
        mac (str): randomized MAC address by mask.

    Raises:
        ValueError: Incorrect format of mask.
    """
    try:
        mask = mask.split(":")
        mask = mask.split("-")
    except ValueError:
        raise ValueError("Incorrect format of MAC generator mask")

    def gen_byte() -> str:
        byte = str(hex(randint(0, 255)))
        return byte[2:] if len(byte[2:]) > 1 else f"0{byte[2:]}"

    return f"{gen_byte() if mask[0] == 'x' else mask[0]}:{gen_byte() if mask[1] == 'x' else mask[1]}:{gen_byte() if mask[2] == 'x' else mask[2]}:{gen_byte() if mask[3] == 'x' else mask[3]}:{gen_byte() if mask[4] == 'x' else mask[4]}:{gen_byte() if mask[5] == 'x' else mask[5]}"


def rand_ssid() -> str:
    """
    Generate random SSID.

    Returns:
        ssid (str): Random generated SSID from 5 to 8 chars.
    """
    length = random.randint(5, 8)
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))
