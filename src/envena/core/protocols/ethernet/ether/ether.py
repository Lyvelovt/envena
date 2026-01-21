# from src.envena.config import scapy, Error_text, Fatal_Error, Clear
# from src.envena.functions import validate_args
from scapy.all import Ether, hexdump, sendp


def send_ether(param, verbose=True) -> bool:
    eth_src = str(param.eth_src).replace("-", ":")
    eth_dst = str(param.eth_dst).replace("-", ":")
    iface = str(param.iface)
    payload = param.payload

    # Creates an Ethernet packet for the data link layer
    ether = Ether(src=eth_src, dst=eth_dst) / payload

    packet = ether

    # Sends the packet
    try:
        sendp(packet, iface=iface, verbose=False)
        if verbose:
            param.logger.info(
                f"Sent Ether: {eth_src} -> {eth_dst}{'' if payload == '' else f': {payload}'}"
            )
            hexdump(packet)
        return True
    except Exception as e:
        param.logger.error(f"Packet was not sent: {e}")
        return False
