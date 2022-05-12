from scapy.all import *
import os
import sys
import time
import change_modes
import helper
import attack

pkt_counter = 0
ap_mac_addr = ""
attack_recognized = False


def get_network_mac():
    """
    Function to find the network mac address that the user is connected to and saves it to a txt file.
    :return:
    """
    global ap_mac_addr
    os.system("sudo rm ap_mac.txt")
    os.system("iwconfig | grep 'Access Point' | tail -1 > ap_mac.txt")
    with open("ap_mac.txt", 'r') as file:
        ap_mac = file.readline().split("Access Point:")[1].strip()
        ap_mac_addr = ap_mac


def defense_handler(pkt):
    """
    The handler for the sniffing in the defense function below.
    Looks for and finds deauthorization packets and alerts the user and makes changes if necessary to defend
    the user from a captive portal attack.
    :param pkt: packet
    :return:
    """
    global pkt_counter, ap_mac_addr, attack_recognized
    print('.')
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
    """
    Main function for the defense tool. Gets the network mac address that the user is connected to and sniffs
    packets on it to find deauthorization packets and alerts the user and makes changes if necessary to defend
    the user from a captive portal attack.
    :param iface: interface name
    :param timeout: length of time in seconds that the defense tool is active
    :return:
    """
    print("\n\nStarting defense protocol from Evil Twin Attack...\n")
    get_network_mac()
    if timeout == 0:
        timeout = 100000  # Sniff for a long...long time
    change_modes.activate_monitor_mode(iface)
    sniff(iface=iface, count=0, prn=defense_handler, timeout=timeout)

