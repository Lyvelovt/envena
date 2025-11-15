from datetime import datetime
from scapy.all import ARP, conf, get_if_hwaddr, IP, Ether
from scapy.all import PcapWriter, sniff
from src.envena.base.arguments import Arguments
from src.envena.base.tool import Tool
from src.envena.functions import validate_ip



import logging
from scapy.all import ARP, IP, Ether
from typing import Dict, Any

def detect_mitm_in_package(
    logger: logging.Logger, 
    packet: Any, 
    ARP_TABLE: Dict[str, str], 
    gateway_ip: str,
    KNOWN_GATEWAY_TTL: Dict
) -> None:
    """
    Анализирует пакет на предмет признаков ARP-спуфинга и MITM.
    """
    
    # --- 1. АКТИВНЫЙ МОНИТОРИНГ (ARP) ---
    if packet.haslayer(ARP):
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc.lower()
        
        # 1.1. ARP Response (op=2: is-at)
        if packet[ARP].op == 2:
            logger.debug(f"ARP response from {source_ip} is at {source_mac}")

            # Игнорируем широковещательные/нереальные ответы (опционально, но полезно)
            if source_mac == 'ff:ff:ff:ff:ff:ff':
                return

            if source_ip in ARP_TABLE:
                # ❗ СВЕРКА MAC-АДРЕСА (Основа детектора)
                if ARP_TABLE[source_ip] != source_mac:
                    # MAC-адрес изменился!
                    logger.critical("ARP-SPOOFING DETECTED (ARP Conflict)!")
                    logger.critical(f"...Conflict IP: {source_ip}")
                    logger.critical(f"...Current MAC: {source_mac} (Attacker/New)")
                    logger.critical(f"...Known MAC..: {ARP_TABLE[source_ip]} (Legitimate)")
                    # Обновляем таблицу, чтобы предотвратить повторное срабатывание
                    ARP_TABLE[source_ip] = source_mac
                # else: pass # MAC совпадает, все ОК
            else:
                # Новый адрес в таблице
                ARP_TABLE[source_ip] = source_mac
                logger.info(f"ARP table updated: {source_ip} -> {source_mac}")

        # 1.2. ARP Request (op=1: who-has)
        elif packet[ARP].op == 1:
            logger.debug(f"ARP request: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")

    # --- 2. ПАССИВНЫЙ МОНИТОРИНГ (IP/ETHERNET) ---
    
    if packet.haslayer(Ether) and packet.haslayer(IP):
        source_ip = packet[IP].src
        source_mac = packet[Ether].src.lower()
        
        # Только если IP-адрес отправителя нам известен
        if source_ip in ARP_TABLE:
            known_mac = ARP_TABLE[source_ip]
            
            # 2.1. L2/L3 Сверка (Обнаружение MITM-перехвата)
            if known_mac != source_mac:
                # Этот пакет отправлен MAC-адресом, отличным от того,
                # который мы знаем для данного IP. Признак того, что кто-то
                # перехватывает трафик (MITM).
                logger.error("MITM DETECTED (L2/L3 Mismatch)!")
                logger.error(f"...Packet Source IP......: {source_ip}")
                logger.error(f"...Packet Source MAC (L2): {source_mac} (Unexpected)")
                logger.error(f"...Known MAC for IP......: {known_mac} (Expected)")
                
            # 2.2. Проверка TTL (для анализа пути)
            if source_ip == gateway_ip:
                # Это опционально, но полезно для подтверждения атаки
                current_ttl = packet[IP].ttl
                
                # Если TTL аномально низок (например, ожидаем 64/128, получаем 63/127 или ниже)
                # Это означает, что пакет прошел через дополнительный хоп (компьютер злоумышленника).
                if current_ttl < (KNOWN_GATEWAY_TTL - 1):
                    logger.warning("TTL Anomaly: Gateway traffic has an unexpected low TTL")
                    logger.warning(f"...Expected TTL: ≈{KNOWN_GATEWAY_TTL}, Received: {current_ttl}. Extra hop suspected")
    

def detect_mitm(param, logger)->None:
    
    if not validate_ip(param.input):
        logger.error('Invalid gateway IP-address got')
        return
    
    ARP_TABLE = {}
    KNOWN_GATEWAY_TTL = {}
    
    ARP_TABLE[param.iface] = get_if_hwaddr(param.iface)
    
    if ARP_TABLE[param.iface] == '00:00:00:00:00:00':
        logger.error('Invalid interface got. Are you use VPN wright now?')
        logger.info(f'Selected interface "{param.iface}" has "00:00:00:00:00:00" MAC-address, that is not allowed for ethernet traffic')
        logger.info('Hint: try turn off VPN or select enother interface')
        return None
    
    now = datetime.now()
    
    filename = f'captured/envena_detect_arpspoof_{now}.pcap'
    try:
        filename = f'captured/envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    except FileNotFoundError:
        filename = f'envena_detect_arpspoof_{now}.pcap'
        pcap_writer = PcapWriter(filename=filename, append=False, sync=True)
    arpspoof_packets = sniff(prn=lambda pkt: detect_mitm_in_package(packet=pkt, logger=logger, ARP_TABLE=ARP_TABLE, 
                            gateway_ip=param.input, KNOWN_GATEWAY_TTL=KNOWN_GATEWAY_TTL), 
                             store=True, iface=param.iface)
    pcap_writer.write(arpspoof_packets)
    logger.info(f'Traffic was writted in "{filename}"')
 

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"ARP-spoofing atack detect module")
    parser.add_argument("-i", "--iface", help="network iface to sniff from", required=False, default=str(conf.iface), type=str)
    parser.add_argument("-g", "--gateway", help="gateway IP-address", required=True, type=str)

    cli_args = parser.parse_args()
    args = Arguments()
    
    args.iface = cli_args.iface
    args.input = cli_args.gateway
    get_if_hwaddr(args.iface)
    
    t_detect_mitm = Tool(tool_func=detect_mitm, VERSION=1.0, args=args)
    
    t_detect_mitm.start_tool()
