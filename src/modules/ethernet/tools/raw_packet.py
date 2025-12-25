from src.envena.base.tool import Tool
from scapy.all import sendp, hexdump, conf
from src.envena.base.arguments import Arguments, public_args

def send_raw_packet(param, printed: bool=True)->bool:
    with open(param.input, 'r') as pkt_file:
        dump = pkt_file.read()
        dump = bytes.fromhex(dump)
    try:
        sendp(dump, verbose=False, iface=param.iface)
        if printed: hexdump(dump)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False

t_raw_packet = Tool(tool_func=send_raw_packet, VERSION=1.1)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Raw packet send script")
    parser.add_argument("-i", "--iface", help="network interface to send from", required=False, default=str(conf.iface), type=str)
    parser.add_argument("-f", "--file", help="the hexstream file to send", required=True, type=str)

    cli_args = parser.parse_args()

    args = Arguments()
    

    public_args.input = cli_args.file
    public_args.iface = cli_args.iface
    
    

    t_raw_packet.start_tool()
