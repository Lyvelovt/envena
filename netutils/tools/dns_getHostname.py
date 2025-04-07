import socket

import sys, os
sys.path.append(os.path.join('..','..'))
from config import *

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def dns_getHostname(args: dict)->None:
    print("DNS get-hostname, version: 1.0")
    print(
        f'DNS response: {args['payload']} is at {get_hostname(ip=args['payload'])}')



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
        print(f'DNS response: {args.ip} is at {get_hostname(args.ip)}')

    except(KeyboardInterrupt):
        print('Successfully aborted.')
        exit(0)