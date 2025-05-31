from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq

# Создание кастомного фрейма (например, Probe Request)
frame = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff") / Dot11ProbeReq() / ("payload")
sendp(frame, iface="wlan0mon", count=100)