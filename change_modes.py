import os
import sys


# Activating monitor mode with required interface name
# def init_attack_mode():
#     os.system("sudo NetworkManager stop")
#     os.system("sudo airmon-ng check kill")

    
def activate_monitor_mode(iface):
    print("Activating monitor mode...")
    #os.system("sudo service network-manager restart")
    #os.system("sudo airmon-ng check kill")
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")
    #os.system("sudo airmon-ng start "+ iface)
    print("Monitor mode activated!")
    return iface
    

def deactivate_monitor_mode(iface):
    print("Deactivating monitor mode")
    # os.system(f"sudo airmon-ng stop {iface}")
    # os.system("sudo systemctl start NetworkManager")
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode managed")
    os.system(f"sudo ifconfig {iface} up")
    print("Monitor mode deactivated and activated managed mode!")


# init_attack_mode()
# activate_monitor_mode(iface)
# deactivate_monitor_mode(iface)

