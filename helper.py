import time
from scapy.all import *
import os


def get_type():
    result = int(input("Choose the type of action to run:\n1- Attack and de-authenticate user from AP\n2- Defend from "
                       "Evil Twin Attack\n3- Exit\n\n"))
    if result not in [1, 2, 3]:
        print("Wrong input, please try again!")
        get_type()
    return result


def scan_channels(iface, channel, typeAP=True):
    if typeAP:
        print(f"Currently scanning for AP's in channel: {channel}")
    else:
        print(f"Currently scanning for users in channel: {channel}")

    os.system(f"sudo iwconfig {iface} channel {channel}")


# Helped using this website: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
def create_hostapd_file(iface, ssid):
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


# Dynamic Host Configuration Protocol (DHCP) server that is used to resolve dns requests from or to a machine and also
# acts as DHCP server to allocate IP addresses to the clients.
# dhcp option=3: IP gateway, option=6: DNS server
# Helped using this website: https://zsecurity.org/how-to-start-a-fake-access-point-fake-wifi/
def create_dnsmasq_file(iface):
    iface = f"interface={str(iface)}\n"
    # address range for the connected network clients. 12h is the amount of hours until the lease expires.
    range = "dhcp-range=192.168.1.2, 192.168.1.30, 255.255.255.0\n"
    option3 = "dhcp-option=3,192.168.1.1\n"  # Gateway IP for the networks.
    option6 = "dhcp-option=6,192.168.1.1\n"  # For DNS Server followed by IP address
    server = "server=8.8.8.8\n"  # DNS server’s address
    queries = "log-queries\n"  # Log the results of DNS queries handled by dnsmasq.
    log_dhcp = "log-dhcp\n"  # Log all the options sent to DHCP clients and the tags used to determine them.
    listen_addr = "listen-address=127.0.0.1\n"  # Links the DHCP to the local IP address which is 127.0.0.1.
    conf_data = iface + range + option3 + option6 + server + queries + log_dhcp + listen_addr
    with open("conf_files/dnsmasq.conf", 'w+') as conf_file:
        conf_file.write(conf_data)
    os.chmod("conf_files/dnsmasq.conf", 0o777)


def delete_conf_files():
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
    """
    os.system(f"iptables --table nat --append POSTROUTING --out-interface {eth} -j MASQUERADE")
    os.system(f"iptables --append FORWARD --in-interface {iface} -j ACCEPT")


def reset():
    delete_conf_files()
    os.system("sudo service NetworkManager start")
    os.system("sudo systemctl stop hostapd")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")
    os.system("sudo systemctl enable systemd-resolved.service")
    os.system("sudo systemctl start systemd-resolved")


def kill_processes():
    os.system("sudo systemctl disable systemd-resolved.service")
    os.system("sudo systemctl stop systemd-resolved")
    os.system("sudo pkill -9 hostapd")
    os.system("sudo pkill -9 dnsmasq")
    os.system("sudo pkill -9 avahi-daemon")
    os.system("sudo pkill -9 dhclient")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")


def ip_tables_config():
    os.system("sudo iptables --flush")
    os.system("sudo iptables --table nat --flush")
    os.system("sudo iptables --delete-chain")
    os.system("sudo iptables --table nat --delete-chain")
    os.system("sudo iptables -P FORWARD ACCEPT")



"""
FIX WIFI QUESTION MARK ????

sudo systemctl enable systemd-resolved.service
sudo systemd-resolve --flush-caches
sudo service network-manager restart


airmon-ng start wlxc83a35c2e0bc


sudo ip link set wlan0mon down
iwconfig
sudo ip link set wlan0mon name wlxc83a35c2e0bc
iwconfig
sudo ip link set wlxc83a35c2e0bc up

"""