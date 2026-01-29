import ipaddress
from typing import List
import re


def parse_ip_ranges(ip_range: str) -> List[str]:
    """
    Parsing Nmap-style IP ranges (Example: 1.1.1.0/24, 1.1.1.1-5, 1.2.3.1,1.2.3.2, e.g.)
    
    Args:
        ip_range (str): Input IP range in Nmap-style.
    
    Returns:
        parsed_ips (List[str]): List of parsed IP addresses.
    
    Raises:
        ValueError: Invalid range to any octet or unsupported IP format.
    """
    elements = [e.strip() for e in ip_range.split(",") if e.strip()]
    parsed_ips: List[ipaddress.IPv4Address] = []

    range_regex = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")

    octet_range_regex = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})(\.\d{1,3})$"
    )

    for element in elements:
        try:
            if "/" in element:
                network = ipaddress.ip_network(element)
                parsed_ips.extend(list(network.hosts()))
            else:
                parsed_ips.append(ipaddress.ip_address(element))

        except ValueError:
            match_last_octet = range_regex.match(element)
            if match_last_octet:
                prefix, start_str, end_str = match_last_octet.groups()
                start, end = int(start_str), int(end_str)

                if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
                    raise ValueError(f"invalid range for last octet: {element}")

                for i in range(start, end + 1):
                    parsed_ips.append(ipaddress.ip_address(f"{prefix}{i}"))
                continue

            match_octet_range = octet_range_regex.match(element)
            if match_octet_range:
                prefix, start_str, end_str, suffix = match_octet_range.groups()
                start, end = int(start_str), int(end_str)

                if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
                    raise ValueError(f"invalid range for middle octet: {element}")

                for i in range(start, end + 1):
                    parsed_ips.append(str(ipaddress.ip_address(f"{prefix}{i}{suffix}")))
                continue

            raise ValueError(f"invalid or unsupported IP format: {element}")

    return parsed_ips

def parse_submask(sub_mask: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network: # Optional[int]:
    """
    Parse subnet mask by input submask.
    
    Args:
        sub_mask (str): Input submask to parse.
    
    Returns:
        network (ipaddress.IPv4Network | ipaddress.IPv6Network | None): Parsed submask or None if unsupported submask format.    
    """
    sub_mask = sub_mask.strip()

    if sub_mask.startswith("/"):
        sub_mask = sub_mask[1:]

    try:
        prefix_len = int(sub_mask)
        if 0 <= prefix_len <= 32:
            return prefix_len
    except ValueError:
        pass

    try:
        network_obj = ipaddress.ip_network(f"0.0.0.0/{sub_mask}", strict=False)
        return network_obj.prefixlen
    except ValueError:
        return None

