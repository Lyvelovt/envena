
from config import *
import scapy.all as scapy

import readline


# ARP
from netutils.arp.request import *
from netutils.arp.response import *

#READY-MADE toolsS
from netutils.tools.arpscan import *
from netutils.tools.dns_getHostname import *
from netutils.tools.detect_arpspoof import *

#RAW PACKET SENDER
from netutils.tools.raw_packet import *
from netutils.tools.ip_forward import *

# DHCP
from netutils.dhcp.discover import *
from netutils.dhcp.ack import *
from netutils.dhcp.offer import *
from netutils.dhcp.request import *
from netutils.dhcp.nak import *
from netutils.dhcp.release import *
from netutils.dhcp.inform import *

print_art()

try:
    while True:
        command = history_input()
        try:
            process_input(command)
        except KeyboardInterrupt:
            print(f"\nAbort.")
        except Exception as e:
            print(f'{Error}Error:{Clear} {Error_text}{e}{Clear}')           
except KeyboardInterrupt:
    print('\n', bye_word)
except Exception as e:
    print(f'{Fatal_Error}Fatal Error:{Clear} {Error_text}{e}{Clear}')
    exit()