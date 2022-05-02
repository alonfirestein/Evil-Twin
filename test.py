from scapy.all import *
import os
import sys
import time
#from helper import *
#from change_modes import *
#from attack import *




a = os.popen("iwconfig").read()
print("START!!!!")
print("wlan0mon" in a)
os.system("sudo NetworkManager stop")
os.system("sudo airmon-ng check kill")
print("wlan0mon" in a)
os.system(f"sudo ifconfig wlxc83a35c2e0bc down")
os.system(f"sudo iwconfig wlxc83a35c2e0bc mode monitor")
os.system(f"sudo ifconfig wlxc83a35c2e0bc up")
os.system("sudo airmon-ng start wlxc83a35c2e0bc")
print("wlan0mon" in a)
print("END!!!!")


os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
with open("iface_name.txt", 'r') as file:
	iface = file.readline().strip()
	
print("interface name is: ", len(iface))
