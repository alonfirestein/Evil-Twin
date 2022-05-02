from scapy.all import *
import os
import sys
import time

import attack
import helper
import change_modes


def main():
    print("Starting Evil Twin Program...\n")
    os.system("iwconfig 2>&1 | grep -oP \"^\w+\" | tail -1 > iface_name.txt")
    with open("iface_name.txt", 'r') as file:
        iface = file.readline().strip()
    print(f"The interface name is: {iface}\n")

    chosen_type = helper.get_type()
    if chosen_type == 1:
        attack.network_attack(iface)    
    
    if chosen_type == 2:
        pass
        
    if chosen_type == 3:
        print("Thanks for using our Evil Twin Program!")
        sys.exit(0)


if __name__ == '__main__':
    main()
