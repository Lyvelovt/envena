# This file contains the functions for the program to work

from random import randint
import random
import string
import socket
from config import Error, Error_text, Clear, Info, Fatal_Error # For colored output
import sqlite3 # To use oui.db
import struct

# Get hostname by DNS protocol (can send DNS request only with your IP, 
# becase based on socket lib)
def get_hostname(ip) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Brute force attack to XID (for now unuseful shit)
def ex_search_xid(from_begin: bool=True)->any:
    if from_begin:
        xid = 1000000
    for xid in range(1000000, 9999999):
        yield xid

# Get subnet IP-address by subnet mask and IP
def get_sub_ip(host_ip: str='0.0.0.0', mask: str='255.255.255.0')->str:
    if host_ip == '0.0.0.0':
        return '0.0.0.0'
    ip_int = struct.unpack('!I', socket.inet_aton(host_ip))[0]
    mask_int = struct.unpack('!I', socket.inet_aton(mask))[0]
    network_int = ip_int & mask_int
    return socket.inet_ntoa(struct.pack('!I', network_int))

def get_ip_broadcast(host_ip: str='0.0.0.0', mask: str='255.255.255.0')->str:
    if host_ip == '0.0.0.0':
        return '0.0.0.0'
    ip_int = struct.unpack('!I', socket.inet_aton(host_ip))[0]
    mask_int = struct.unpack('!I', socket.inet_aton(mask))[0]
    broadcast_int = ip_int | (~mask_int & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack('!I', broadcast_int))

# Print or get manufacturer's company from oui.db by OUI of MAC address
def get_manufacture(eth: str=None, printed: bool=False)-> bool | str: # str if not printed
    if not validate_args(input=eth):
        return False, ''
    if not validate_eth(eth=eth, is_oui=True if len(eth.split(':')) == 3 else False):   
        if printed:
            print(f'Invalid eth-address "{eth}".')
        return False
    else:
        eth = eth[:8] if len(eth) == 17 else eth
        conn = sqlite3.connect("database/oui.db") # Connecting to database
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT manufacturer FROM oui WHERE mac_prefix = ?",
            (eth.lower(),)
        )
        
        result = cursor.fetchone()
        conn.close()
        if result:
            if printed:
                print(f'Manufacture of "{eth}" is {result[0]}')
                return True
            else:
                return result[0]
        else:
            if printed:
                print(f'Failed to find manufacturer of "{eth}" from database.')
                return False
            else:
                return "Unknown"
            
# Check all args are not None
def validate_args(**kwargs)->None:
    noneIsFount = True
    for arg_name, arg_value in kwargs.items():
        if arg_value is None:
            print(f"{Error}Error: {Error_text}arg \"{arg_name}\" is required!{Clear}")
            noneIsFount = False
    return noneIsFount

# Validate IP-address
def validate_ip(ip: str = '') -> bool:
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        
        for octet in octets:
            if not octet.isdigit():
                return False
            num = int(octet)
            if not 0 <= num <= 255:
                return False
                
        return True
    except (ValueError, AttributeError):
        return False

# Validate eth-address
def validate_eth(eth: str = '', is_oui: bool = False) -> bool:
    try:
        if not isinstance(eth, str):
            return False
            
        hex_chars = set("0123456789abcdefABCDEF")
        parts = eth.split(':')
        
        if is_oui:
            if len(parts) != 3 or any(len(p) != 2 for p in parts):
                return False
        else:
            if len(parts) != 6 or any(len(p) != 2 for p in parts):
                return False
                
        return all(c in hex_chars for part in parts for c in part)
    except (ValueError, AttributeError):
        return False

# Returned random IP-address by mask or not
def rand_ip(mask: str='0.0.0.0')->str:
    if not mask or not validate_ip(ip=mask):
        print(f'{Info}Info: there is not IP-address mask in "input" argument.{Clear}')
        mask = '0.0.0.0'
    mask = mask.split('.')
    return f"{str(randint(0, 255)) if mask[0] == '0' else mask[0]}.{str(randint(0, 255)) if mask[1] == '0' else mask[1]}.{str(randint(0, 255)) if mask[2] == '0' else mask[2]}.{str(randint(0, 255)) if mask[3] == '0' else mask[3]}"

# Returned random eth-address by mask or not
def rand_eth(mask: str='00:00:00:00:00:00')->str:
    if not mask or not validate_eth(eth=mask, is_oui=False):
        print(f'{Info}Info: there is not MAC-address mask in "input" argument.{Clear}')
        mask = '00:00:00:00:00:00'
    mask = mask.split(':')
    def gen_byte()->str:
        byte = str(hex(randint(0, 255)))
        return byte[2:] if len(byte[2:]) > 1 else f"0{byte[2:]}"
    return f"{gen_byte() if mask[0] == '00' else mask[0]}:{gen_byte() if mask[1] == '00' else mask[1]}:{gen_byte() if mask[2] == '00' else mask[2]}:{gen_byte() if mask[3] == '00' else mask[3]}:{gen_byte() if mask[4] == '00' else mask[4]}:{gen_byte() if mask[5] == '00' else mask[5]}"

def rand_ssid():
    length = random.randint(5, 8)
    characters = string.ascii_letters + string.digits  # латинские буквы + цифры
    return ''.join(random.choices(characters, k=length))

# Emergency exit from the program in case of fatal failure and write info in "envena_panic.log"
def envena_panic(exc_type, exc_value, exc_traceback)->None:
    from datetime import datetime
    time = datetime.now() # Get panic time
    
    import traceback
    import platform
    import os
    import sys
    
    print(f'{Fatal_Error}[{time}]: {Error_text}Envena panicked! ({exc_value}){Clear}')
    print(f'''{Info}Info: Report this incident by writing to "https://github.com/Lyvelovt",
describing the problem and attaching the file "envena_panic.log" (it is located in the
directory with "envena.py"), the history of the Envena Shell (what you entered and
what led to the error) and scapy "WARNING:"'s. You can also view the details of the incident
in this file. The information contained in the "envena_panic.log":
 |- 1. Panic time.
 |- 2. Description of the Python interpreter error (may contain the names of the directory 
 |     where the program is located and the user name).
 |- 3. The platform on which the error was received.
 |- 4. The python version.
 |- 5. Is the program running as root/admin/superuser?{Clear}''')
    
    with open("envena_panic.log", "a", encoding='utf-8') as f:
        f.write(f"\n[{time}] [!] Unhandled exception:\n")
        f.write(f"# System: {platform.system()} {platform.release()} ({platform.version()})\n")
        f.write(f"# Python: {platform.python_version()} ({platform.python_implementation()})\n")
        f.write(f"# Admin/root: {'YES' if os.name != 'nt' and os.geteuid() == 0 else 'NO'}\n")
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
    sys.exit()