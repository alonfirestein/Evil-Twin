from scapy.all import *
import os
import sys
import time
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
import change_modes
import helper
import attack

pkt_counter = 0
ap_mac_addr = ""
attack_recognized = False


def get_network_mac():
    global ap_mac_addr
    # print("Please enter the MAC address of the WIFI network you are connected to.\n"
    #       "The wireless MAC address will be in the field labeled 'HWaddr'.")
    str(os.system("iwconfig | grep 'Access Point' | tail -1 > ap_mac.txt"))
    with open("ap_mac.txt", 'r') as file:
        ap_mac = file.readline().split("Access Point:")[1].strip()
        ap_mac_addr = ap_mac


def defense_handler(pkt):
    global pkt_counter, ap_mac_addr, attack_recognized
    gmt_time = time.gmtime(time.time())
    # Packet type 0 & subtype 12 => de-authentication packet.
    if pkt.type == 0 and pkt.subtype == 12 and ap_mac_addr == str(pkt.addr2):
        pkt_counter += 1
    if pkt_counter % 10 == 0 and pkt_counter != 0:
        print(f"WARNING: {pkt_counter} deauthentication packets have been recognized on your network!")
    # If we get more than 100 of these packets
    if pkt_counter >= 50:
        print("Evil Twin Attack Recognized! Restarting NetworkManager to prevent attack!")
        attack_recognized = True
        os.system("sudo service network-manager restart")
    if gmt_time.tm_sec == 0 and not attack_recognized:
        pkt_counter = 0

    """
    Once we recognize an official attack, this next line will block all connections from the input IP address
    """
    # os.system(f"iptables -A INPUT -s {attacker_ip} -j DROP")


def defend(iface, timeout=60):
    get_network_mac()
    sniff(iface=iface, count=0, prn=defense_handler, timeout=timeout)

