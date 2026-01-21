from scapy.all import BOOTP, DHCP, IP, UDP, Ether, hexdump, sendp


def send_dhcp_inform(param, verbose: bool = True) -> bool:
    ip_dst = str(param.ip_dst)
    ip_src = str(param.ip_src)
    # eth_dst=str(param.eth_dst)
    xid = param.xid
    # lease_time=param.lease_time
    # sub_mask=str(param.sub_mask)
    # dns_server=str(param.dns_server)
    iface = param.iface
    eth_src = str(param.eth_src)
    port_src = param.port_src
    port_dst = param.port_dst
    hostname = param.hostname
    param_req_list = param.param_req_list

    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
    ip = IP(src=ip_src, dst=ip_dst)
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(chaddr=eth_src.encode(), xid=xid)

    dhcp_options = [
        ("message-type", 8),  # DHCP Inform
        ("client_id", b"\x01" + bytes.fromhex(eth_src.replace(":", ""))),
        ("server_id", ip_dst),
        ("requested_addr", ip_src),
        ("hostname", hostname),
        ("param_req_list", param_req_list),
        ("end"),
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp

    try:
        sendp(packet, iface=iface, verbose=False)
        if verbose:
            param.logger.info(f"Sent inform: {ip_src} -> {ip_dst}: Inform {ip_src}")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False
