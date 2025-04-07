
<img width="592" alt="envena.png" src="https://github.com/user-attachments/assets/350c95fe-1b9c-4a26-897d-c0edc06bb550" />


# envena
### DESCRIPTION ###
<b>Envena</b> - is a powerful tool for generating custom network packets and manipulating them. The user has full control over the protocol headers. This opens up a lot of possibilities. The program is designed as an interactive shell (which makes management user-friendly) and uses a simple syntax. Users can create their own modules, functions, and so on, because the program is designed in a modular way.

### MAIN OBJECTIVES ###
The <b>Envena</b> project aims to create a universal tool for analyzing, generating and processing network packets for educational and practical cybersecurity purposes. Key goals include:

• <b>Flexible packet generation:</b> creating packets with arbitrary parameters (or even with arbitrary content) to simulate various network scenarios.

• <b>Protocol support:</b> Implemented ARP and DHCP support. It is planned to add TCP, UDP, ICMP, DNS, 802.1X, as well as modules for working with cryptography (public and private keys, etc.).

• <b>Scripts for analysis and diagnostics:</b> ready-made modules for network scanning, attack detection, domain name identification, and more.

• Cross-platform.

### Requirements ###

• <b>The Python3 Interpreter.</b>

• <b>The installed Scapy library.</b>

• <b>Network adapter (internal or external, laptops and phones
have internal built-in Wi-Fi network adapters by default).</b>

• <b>Superuser rights (“root” or “administrator rights”), because
the project uses a lower level of abstraction.</b>

The possibilities expand significantly with an external Wi-Fi adapter that supports monitoring mode. Envena is a very powerful and flexible tool that allows you to create custom packets up to the Ethernet header. So far, the tool supports only 2 protocols, but the user can independently assemble packets of any protocol (so far, only stack Ethernet protocols. In the future, it is planned to create a graphical interface with a form for such collection of packages. The project supports a bunch of types of network testing, I can give you a couple of basic ones as an example.:

• ARP-spoofing

• DHCP-spoofing

• Denay Of Service

• Packet inject

• Sending malformed (corrupted) packets

• ARP-spoofing detection

• Man-In-The-Middle

• DNS-spoofing

• CAM-overflow

• Replay attack

... and others. You can also use this tool to test various protocols for vulnerabilities.
