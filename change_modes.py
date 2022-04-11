import os


def active_monitor_mode(interface):
    os.system("sudo ip link set "+ interface+ " down")
    os.system("sudo iw "+ interface+  " set monitor none")
    os.system("sudo ip link set "+ interface+ " up")
    return interface
    
    
def monitor_mode_airmon(interface):
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start "+ interface)
    interface = str(interface)+'mon'
    return interface




