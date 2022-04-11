import os
import sys

os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
with open("iface_name.txt", 'r') as file:
	iface = file.readline()
	
print(f"The interface name is: {iface}")
# iface = sys.argv[1]

# Activating monitor mode with required interface name
def active_monitor_mode(iface):
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start "+ iface)
    return iface
    
    
    


# Running needed commands
active_monitor_mode(iface)



