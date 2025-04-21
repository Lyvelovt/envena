from config import *
help_info = f"""
Envena v{envena_version}.

### AVAILABLE COMMANDS ###
arp.request         -    send ARP-request.
arp.response        -    send ARP-reply.
dhcp.discover       -    send DHCP-discover.
dhcp.offer          -    send DHCP-offer.
dhcp.request        -    send DHCP-request.
dhcp.ack            -    send DHCP-ack.
dhcp.nak            -    send DHCP-nak.
dhcp.release        -    send DHCP-release.
dhcp.info           -    send DHCP-info.
list                -    show all value of args.
exit                -    exit from envena shell.
help                -    show this text.
?                   -    the same as 'help'.

### READY-MADE TOOLS ###
tools.raw_packet          -    reads raw packet from file and sends it.
tools.arpscan             -    scanning network using ARP protocol. Input ip
                            range must be in 'input' and use format 'x.x.x.x-255'.
                            Output is IP|MAC|HOSTNAME.
tools.dns_getHostname     -    send DNS protocol request from your's MAC and IP addresses.
                            Get hostname by IP-address. Output is variable of hostname.
tools.detect_arpspoof     -    sniffs traffic and detects packets with duplicate addresses,
                            which may indicate ARP spoofing.
tools.ip_forward          -   performs IP forwarding between specified addresses (P.S. this
                            shit isn't working yet). Captures and stores traffic in PCAP
                            file with timestamp.
tools.cam_overflow        -   performs CAM table overflow attack by sending random MAC addresses.
tools.dhcp_starve         -   performs DHCP starvation attack by sending DHCP Discover packets.


### AVAILABLE ARGS ###
ip_dst        -    destination-IP address.
ip_src        -    source IP-address, by default - your IP address.
port_dst      -    destination port.
port_src      -    source port.
mac_dst       -    destination MAC-address.
mac_src       -    source MAC-address, by default - your MAC-address.
count         -    count of packets to send.
timeout       -    timeout between sending packets in seconds.
iface         -    network interface.
input         -    input or specific input data for module.
sub_mask      -    sudnet mask. Default = 255.255.255.0.
xid           -    XID for DHCP packets.
dns_server    -    DNS server for getting IP-address from domen.
                      Default = 8.8.8.8 (Google Public DNS).


### INFORMATION ###
1. By default all args is 'None'. 'None' source arg contains your default information.
That is, if 'ip_src=None' (this applies to the rest of the arguments,
not just ip_src), then the packet will be sent under your IP-address.
2. You can leave the value of the arg empty, in this case it will 
take the value zero. That is, if 'ip.src=', then the sender's address in 
the packet will be specified as 0x00.0x00.0x00.0x00, in other words, 'no address'.


### MODULES INFO ###
--- ARP ---

arp.request:
    ip_dst      -       the IP address of the device whose MAC address is being requested.
    ip_src      -       source IP address.
    mac_dst     -       destination MAC address (default: broadcast).
    mac_src     -       source MAC-address.

arp.response:
    ip_dst      -       destination IP address (default: ip_broadcast).
    ip_src      -       source IP address, who is telling his MAC address.
    mac_dst     -       destination MAC address (default: broadcast).
    mac_src     -       source MAC-address, that will be telling.

--- DHCP ---

dhcp.discover:
    xid         -       transaction ID (randomly generated if None).
    port_src    -       source UDP port (default: 68).
    port_dst    -       destination port (default: 67).
    mac_src     -       source MAC address.
    iface       -       network interface (optional).

dhcp.ack:
    ip_dst      -       IP address to assign to the client.
    ip_src      -       DHCP server IP address.
    mac_dst     -       client's MAC address.
    xid         -       transaction ID (random if None).
    sub_mask    -       subnet mask (default: "255.255.255.0").
    dns_server  -       DNS server IP (default: "8.8.8.8").
    iface       -       network interface to use (optional).
    mac_src     -       server MAC address (optional).
    port_src    -       source UDP port (default: 67).
    port_dst    -       destination UDP port (default: 68).

dhcp.offer:
    ip_dst      -       offered IP address.
    ip_src      -       DHCP server IP.
    mac_dst     -       client's MAC address.
    xid         -       transaction ID (random if None).
    sub_mask    -       subnet mask (default: "255.255.255.0").
    dns_server  -       DNS server IP (default: "8.8.8.8").
    iface       -       network interface (optional).
    mac_src     -       server MAC address (optional).
    port_src    -       source UDP port (default: 67).
    port_dst    -       destination UDP port (default: 68).

dhcp.release:
    ip_src      -       client's current IP address.
    ip_dst      -       DHCP server IP.
    xid         -       transaction ID (random if None or 'rand_xid').
    iface       -       network interface (optional).
    mac_src     -       client's MAC address (required).
    port_src    -       source UDP port (default: 68).
    port_dst    -       destination UDP port (default: 67).

dhcp.request:
    ip_src      -       requested IP address.
    ip_dst      -       DHCP server IP.
    xid         -       transaction ID (random if None).
    iface       -       network interface (optional).
    mac_src     -       client's MAC address (required).
    port_src    -       source UDP port (default: 68).
    port_dst    -       destination UDP port (default: 67).

dhcp.inform:
    ip_src      -       client's current IP address.
    ip_dst      -       DHCP server IP.
    xid         -       transaction ID (random if None).
    iface       -       network interface (optional).
    mac_src     -       client's MAC address.
    port_src    -       source UDP port (default: 68).
    port_dst    -       destination UDP port (default: 67).

--- READY-MADE TOOLS ---

arpscan:
    input       -       IP range to scan (format: "192.168.1.1" or "192.168.1.1-100").
    mac_src     -       source MAC address for ARP packets.
    ip_src      -       source IP address for ARP packets.
    iface       -       network interface to use.

cam_overflow:
    iface       -       network interface to use.
    input       -       payload content (default: 64 'X' characters).
    mac_dst     -       target MAC address (optional).
    timeout     -       packets per second rate (default: 500).

dhcp_starve:
    iface       -       network interface to use.

dns_getHostname:
    input       -       IP address to resolve.

send_raw_packet:
    input       -       path to file containing raw packet data in hex format.
    iface       -       network interface to use (optional).

ip_forward:
    ip_dst      -       destination IP address.
    mac_dst     -       destination MAC address.
    ip_src      -       source IP address (router).
    mac_src     -       source MAC address (router).
    iface       -       network interface to use.
"""


