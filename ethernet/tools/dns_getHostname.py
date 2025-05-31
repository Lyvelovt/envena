import sys
import os
sys.path.append(os.path.join('..','..'))
from functions import validate_args, get_hostname
dns_getHostname_v = 1.0



def dns_getHostname(args: dict)->None:
    if not validate_args(input=args['input']):
        return False
    print(f"DNS get-hostname, version: {dns_getHostname_v}")
    print(
        f'DNS response: {args['input']} is "{get_hostname(ip=args['input'])}".')




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
        parser.add_argument("-ip", help="target IP.", required=True)  # , required=True)
        # parser.add_argument( "-i", "--interface", help="Network interface.")

        arg = parser.parse_args()
        args = {}
        args['input'] = arg.ip
        dns_getHostname(args)

    except(KeyboardInterrupt):
        print('Aborted.')
        exit(0)
