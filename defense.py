from scapy.all import *
import os
import sys
import time
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
import change_modes
import helper
import attack


def defense_handler(pkt):
    # client_mac = pkt[Dot11].addr3
    pkt_counter = 0
    # Packet type 0 & subtype 12 => de-authentication packet.
    if pkt.type == 0 and pkt.subtype == 12: #and client_mac == mac:
        pkt_counter += 1
    # If we get more than 100 of these packets
    if pkt_counter > 100:
        print("Evil Twin Attack Recognized! SHUT DOWN NOW!")

    # Once we recognize an attack, this next line will block all connections from the input IP address
    # os.system(f"iptables -A INPUT -s {attacker_ip} -j DROP")


def defend(iface):
    sniff(iface=iface, count=0, prn=defense_handler, timeout=20)