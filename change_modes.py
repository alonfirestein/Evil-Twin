import os
import sys

os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
with open("iface_name.txt", 'r') as file:
	iface = file.readline()
	
print(f"The interface name is: {iface}")
# iface = sys.argv[1]

# Activating monitor mode with required interface name
def active_monitor_mode(iface):
	print("Activating monitor mode")
    os.system("sudo service network-manager restart")
    os.system("sudo airmon-ng check kill")
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")
    #os.system("sudo airmon-ng start "+ iface)
    return iface
    

def deactivate_monitor_mode(iface):
	print("Deactivating monitor mode")
	os.system(f"sudo airmon-ng stop {iface}")
    os.system("sudo systemctl start NetworkManager")
    
    
    


# Running needed commands
active_monitor_mode(iface)
#deactivate_monitor_mode(iface)


