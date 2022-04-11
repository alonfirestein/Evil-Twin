import os
import sys

iface = sys.argv[1]

def active_monitor_mode(iface):
    os.system("sudo ifconfig "+ iface+ " down")
    os.system("sudo iwconfig "+ iface+  " mode monitor")
    os.system("sudo ifconfig "+ iface+ " up")
    return iface
    
    
def monitor_mode_airmon(iface):
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start "+ iface)
    interface = str(iface)+'mon'
    return iface
    
    



active_monitor_mode(iface)
monitor_mode_airmon(iface)


