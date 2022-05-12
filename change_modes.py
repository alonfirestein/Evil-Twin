import os
import sys


# Activating monitor mode with required interface name
def init_attack_mode():
    os.system("sudo NetworkManager stop")
    os.system("sudo airmon-ng check kill")

    
def activate_monitor_mode(iface):
    """
    Activating monitor mode
    :param iface: interface name
    :return:
    """
    print("Activating monitor mode...")
    os.system(f"sudo airmon-ng start {iface}")
    os.system(f"sudo ip link set wlan0mon down")
    os.system(f"sudo ip link set wlan0mon name {iface}")
    os.system(f"sudo ip link set {iface} up")

    # os.system(f"sudo ifconfig {iface} down")
    # os.system(f"sudo iwconfig {iface} mode monitor")
    # os.system(f"sudo ifconfig {iface} up")

    print("Monitor mode activated!")
    return iface
    

def deactivate_monitor_mode(iface):
    """
    Deactivating monitor mode back to managed mode
    :param iface: interface name
    :return:
    """
    print("Deactivating monitor mode")
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode managed")
    os.system(f"sudo ifconfig {iface} up")
    print("Monitor mode deactivated and activated managed mode!")


