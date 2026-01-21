from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, hexdump

def send_dhcp_ack(param, printed: bool=True)->bool:
    ip_dst=str(param.ip_dst)
    ip_src=str(param.ip_src)
    eth_dst=str(param.eth_dst)
    xid=param.xid
    lease_time=param.lease_time
    sub_mask=str(param.sub_mask)
    dns_server=str(param.dns_server)
    iface=param.iface
    eth_src=str(param.eth_src)
    port_src=param.port_src
    # hostname=param.hostname
    port_dst=param.port_dst
    # param_req_list=param.param_req_list

    ether = Ether(dst=eth_dst, src=eth_src)
    ip = IP(src=ip_src, dst=ip_dst)
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(op=2, yiaddr=ip_dst, chaddr=eth_dst.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 5),  # DHCP ACK
        ("server_id", ip_src),
        ("lease_time", lease_time),
        ("sub_mask", sub_mask),
        ("router", ip_src),
        ("dns", dns_server),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp

    try:
        sendp(packet, iface=iface, verbose=False)
        if printed:
            param.logger.info(f"Sent ack: {ip_src} -> {ip_dst}: Address issue acknowledgement")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False 
