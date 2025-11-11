from src.envena.functions import get_hostname
dns_getHostname_v = 1.0

def dns_getHostname(param)->None:
    print(
        f'DNS response: {args['input']} is "{get_hostname(ip=args['input'])}".')



if __name__ == "__main__":
    try:
        import time
        start_time = time.time()
        
        import argparse

        parser = argparse.ArgumentParser(description="Script witch get host domain name by IP-address", formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("-ip", help="target IP.", required=True)  # , required=True)
        # parser.add_argument( "-i", "--interface", help="Network interface.")

        arg = parser.parse_args()
        args = {}
        args['input'] = arg.ip
        dns_getHostname(args)

    except(KeyboardInterrupt):
        print('Aborted.')
        exit(0)
