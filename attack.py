from scapy.all import * 
import os
import sys
import time
import change_modes as modes


# Global Variables
iface = ""
ap_list = []
ssid_list = []


def scan_wlan():
    print("Scanning for access points...")
    print("index\tMAC\tSSID")
    sniff(iface = iface, prn = AP_handler)



def AP_handler(pkt) :
    global ap_list
    # Checking if the packets have a 802.11 layer
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2 )
                ssid_list.append(pkt.info)
                print(f"{len(ap_list)}\t{ pkt.addr2}\t{pkt.info}")





scan_wlan()
