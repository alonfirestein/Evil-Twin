from scapy.all import *
import os
import sys
import time
import helper

from scapy.all import *
from threading import Thread
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

print("This is the file used for testing.")

#helper.create_hostapd_file("wlxc83a35c2e0bc", "benitacomputer")
#helper.create_dnsmasq_file("wlxc83a35c2e0bc")

helper.enable_nat("enp2s0f0")
#helper.start_ap()
#helper.stop_ap()

