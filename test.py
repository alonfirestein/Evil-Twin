from scapy.all import *
import os
import sys
import time
#from helper import *
#from change_modes import *
#from attack import *


from scapy.all import *
from threading import Thread
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap


def send_beacon(ssid, mac, infinite=True):
	dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
	# type=0:       management frame
	# subtype=8:    beacon frame
	# addr1:        MAC address of the receiver
	# addr2:        MAC address of the sender
	# addr3:        MAC address of the Access Point (AP)

	# beacon frame
	beacon = Dot11Beacon()

	# we inject the ssid name
	essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

	# stack all the layers and add a RadioTap
	frame = RadioTap() / dot11 / beacon / essid

	# send the frame
	if infinite:
		sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)
	else:
		sendp(frame, iface=iface, verbose=0)


if __name__ == "__main__":
	os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
	with open("iface_name.txt", 'r') as file:
		iface = file.readline().strip()

	print("interface name is: ", iface)
	import argparse

	# generate random SSIDs and MACs
	fake_mac_addr = RandMAC()
	print(f"Fake mac addr is: {fake_mac_addr}")
	ssids_macs = [("AlonFakeAPNow", fake_mac_addr)]
	for ssid, mac in ssids_macs:
		Thread(target=send_beacon, args=(ssid, mac)).start()


