from scapy.all import * 
import os
import sys
import sys
import time
import random
import change_modes as modes


# Global Variables
iface = sys.argv[1]
ap_set = set()
ssid_set = set()


def scan_wlan():
    print("Scanning for access points...")
    print("index\tMAC\t\t\tSSID")
    sniff(iface = iface, count = 0, prn = AP_handler, timeout = 30)



def AP_handler(pkt) :
    global ap_list
    # Checking if the packets have a 802.11 layer
    if pkt.haslayer(Dot11): # and pkt.type == 0 and pkt.subtype == 8:
    	dot11_layer = pkt.getlayer(Dot11)
            if dot11_layer.addr2 and dot11_layer not in ap_set and dot11_layer.payload.name != "NoPayload":
                ap_set.add(dot11_layer.addr2 )
                ssid_set.add(dot11_layer.payload.name)
                print(f"{len(ap_set)}\t{ dot11_layer.addr2}\t{dot11_layer.payload.name}")




# Main
scan_wlan()
print("\nAccess Points Captured:\n\n",'\n'.join(ap_set))

random_ap = random.sample(ap_set, 1)
print(f"Random chosen AP is: {random_ap[0]}")
