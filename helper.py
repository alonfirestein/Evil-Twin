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
