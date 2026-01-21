from scapy.all import BOOTP, DHCP, IP, UDP, Ether, hexdump, sendp


def send_dhcp_release(param, verbose: bool = True) -> bool:
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
    # hostname=param.hostname
    # param_req_list=param.param_req_list
    # ip_router=str(param.ip_router)

    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=port_src, dport=port_dst)
        / BOOTP(
            op=1, chaddr=bytes.fromhex(eth_src.replace(":", "")), ciaddr=ip_src, xid=xid
        )
        / DHCP(
            options=[
                ("message-type", "release"),
                ("client_id", b"\x01" + bytes.fromhex(eth_src.replace(":", ""))),
                ("server_id", ip_dst),
                ("requested_addr", ip_src),
                "end",
            ]
        )
    )

    try:
        sendp(packet, iface=iface, verbose=False)
        if verbose:
            param.logger.info(
                f"Sent release: {ip_src} -> {ip_dst}: {ip_src} has been released"
            )
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False
