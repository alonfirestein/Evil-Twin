from scapy.all import *
import os
import sys
import time
import defense
import attack
import helper


"""
Main function that initializes the Evil Twin program and lets the user decide whether to attack or defend.
"""
def main():
    print("Starting Evil Twin Program...\n")
    helper.iface_name_to_file()
    with open("iface_name.txt", 'r') as file:
        iface = file.readline().strip()
    print(f"The interface name is: {iface}\n")

    chosen_type = helper.get_type()
    if chosen_type == 1:
        attack.network_attack(iface)    
    
    if chosen_type == 2:
        timeout = input("\nFor how long would you like to run the 'Evil Twin Defense Tool'?\n"
                        "(0 for unlimited until manually stopped) - ")
        if timeout.isnumeric():
            timeout = int(timeout)
        else:
            timeout = int(input("\nPlease enter a number in seconds (0 for unlimited until manually stopped) - "))
        defense.defend(iface, timeout)
        
    if chosen_type == 3:
        print("Thanks for using our Evil Twin Program!")
        sys.exit(0)


if __name__ == '__main__':
    main()
