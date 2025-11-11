from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, hexdump

def send_dhcp_request(param, printed: bool=True)->bool:
    ip_dst=str(param.ip_dst)
    ip_src=str(param.ip_src)
    # eth_dst=str(param.eth_dst)
    xid=param.xid
    # lease_time=param.lease_time
    # sub_mask=str(param.sub_mask)
    # dns_server=str(param.dns_server)
    iface=param.iface
    eth_src=str(param.eth_src)
    port_src=param.port_src
    port_dst=param.port_dst
    hostname=param.hostname
    # param_req_list=param.param_req_list
    # ip_router=str(param.ip_router)
    
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=eth_src)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=port_src, dport=port_dst)
    bootp = BOOTP(chaddr=eth_src.encode(), xid=xid)
    dhcp_options = [
        ("message-type", 3),  # DHCP Request
        ("client_id", b"\x01" + bytes.fromhex(eth_src.replace(":", ""))),
        ("requested_addr", ip_src),
        ("server_id", ip_dst),
        ("hostname", hostname),
        ("param_req_list", [1, 3, 15, 6]),
        ("end")
    ]
    dhcp = DHCP(options=dhcp_options)

    packet = ether / ip / udp / bootp / dhcp
    
    try:
        sendp(packet, iface=iface, verbose=False)
        if printed:
            param.logger.info(
                f"Sent request: {ip_src} -> 255.255.255.255: Requested address accepted. {ip_src} is at {eth_src}")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False
