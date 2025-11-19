from scapy.all import ICMP, IP, hexdump, Ether, sendp

def send_icmp_echo_request(param, printed=True)->bool:
    ip_src = str(param.ip_src)
    ip_dst = str(param.ip_dst)
    eth_src = str(param.eth_src).replace('-', ':')
    eth_dst = str(param.eth_dst).replace('-', ':')
    iface = str(param.iface)
    ttl = param.ttl
    seq = param.seq
    id_ = param.id
    payload = param.payload
    
    packet = Ether(
        src=eth_src,
        dst=eth_dst
        ) / IP(
        dst=ip_dst,
        src=ip_src,
        ttl=ttl
        ) / ICMP(
        id=id_,
        seq=seq,
        type=8
    )
    if payload:
        packet / payload


    # Sends the packet
    try:
        sendp(packet, iface=iface, verbose=False)
        if printed:
            param.logger.info(f"Sent echo request: {ip_src} -> {ip_dst}")
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False