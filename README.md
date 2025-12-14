<img width="1192" height="598" alt="envena" src="https://github.com/user-attachments/assets/a82f5139-d627-469c-a6be-3674fc90ce9d" />

# Envena: Network Vulnerability Exposure Node Analyzer 
### Description
<b>Envena</b> - is a program for network analysis and testing that includes:
```
1. Scripts for diagnostics and analysis, which are in demand in everyday situations
2. Flexible generation of packets with arbitrary headers
3. Support for key protocols: ARP (L2/3), DHCP (L7), ICMP (L3), IEEE 802.11 (L1/2)
4. Cross-platform
```

### Requirements
```
• Python3 Interpreter
• Installed scapy library
• Root rights
```

### Scope
The possibilities expand significantly with an external Wi-Fi adapter that supports monitoring mode.
Example of the main features:
```
•ARP-spoofing              •ICMP tracing
•DHCP-spoofing             •802.11 deauthentication jam
•Denay Of Service          •802.11 traffic scanning
•Packet inject             •ARP scanning
•Sending malformed packets •Device location detection by trilateration of 802.11 traffic
•ARP-spoofing detection    •MITM detecting
•Man-In-The-Middle         •IP forwarding
•DHCP-starvation           •Get domain name by IP address
•Replay attack             •CAM-overflow
... and others. You can also use this tool to test various protocols for vulnerabilities or build your own module.
```

### Installation
Unix-like systems:
```sh
git clone https://github.com/Lyvelovt/envena.git
cd envena
python3 -m venv venv
source venv/bin/activate.sh
pip install -r requirements.txt
```

Windows (cmd):
```bat
git clone https://github.com/Lyvelovt/envena.git
cd envena
python3 -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

Windows (PowerShell):
```PowerShell
git clone https://github.com/Lyvelovt/envena.git
cd envena
python3 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Using
Example for Unix-like systems:
```sh
# To scan all subnet for hosts using ARPscan module
sudo python3 -m src.ethernet.tools.arpscan -ip 192.168.1.0/24
```

To run any other module use:
```sh
sudo python3 -m <path to module in python import standart> <args>
```
Example for Windows:

Start your terminal with <b>superuser</b> rights!
```
# To scan all subnet for hosts using ARPscan module
python3 -m src.ethernet.tools.arpscan -ip 192.168.1.0/24
```

To run any other module use:
```
python3 -m <path to module in python import standart> <args>
```
