from scapy.all import *
import os
import sys
import time

import attack
import helper
import defense
import change_modes
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
ap_list = []

iface = "wlxc83a35c2e0bc"
victim = "0c:54:15:70:8b:ef"
print("This is the file used for testing.")

# attack.create_fake_ap(iface, victim, ap_name="FakeAPHere!")
# attack.activate_fake_ap(iface, ssid="FakeAPHere!")

gmt = time.gmtime(time.time())
print(f"The current time is: {gmt.tm_sec}")
