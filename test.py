from scapy.all import *
import os
import sys
import time

import attack
import helper
import change_modes
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
ap_list = []

iface = "wlxc83a35c2e0bc"
print("This is the file used for testing.")

helper.reset()
