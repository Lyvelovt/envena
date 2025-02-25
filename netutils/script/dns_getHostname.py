import socket

import sys
sys.path.append('..'*2)
from config import *

def get_hostname(ip):
    """Получает имя хоста (DNS) по его IP-адресу."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def dns_getHostname(args):
    print("*DNS get-hostname, version: 1.0")
    print(
        f'{Back}DNS response: {Orange}{args['payload']}{Clear}{Back} {Purple}is at{Clear}{Back} {Light_blue}{get_hostname(ip=args['payload'])}{Clear}{Clear}')



if __name__ == "__main__":
    try:
        import time
        start_time = time.time()
        
        import argparse

        desc = '''Get hostname by IP address using DNS protocol\n
        \n
        base using:
          get_hostname -ip <192.168.1.10>
        '''

        parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("ip", help="target IP.")  # , required=True)
        # parser.add_argument( "-i", "--interface", help="Network interface.")

        args = parser.parse_args()
        print("DNS-get_hostname, version: 1.0.")
        get_hostname(args.ip)
        # print('-'*len(dns[0]))
        # print(dns[0])
        # for _ in dns[1]:
        #     print(_)
        # for _ in dns[2]:
        #     print(_)
        # print('-' * len(dns[2][len(dns[2])-1]))
        print(f'{Back}DNS response: {Orange}{args.ip}{Clear}{Back} {Purple}is at{Clear}{Back} {Light_blue}{get_hostname(args.ip)}{Clear}{Clear}')

    except(KeyboardInterrupt):
        print('Successfully aborted.')
        exit(0)