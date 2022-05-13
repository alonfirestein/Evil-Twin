# Evil-Twin  
  
[An evil twin attack](https://www.pandasecurity.com/en/mediacenter/security/what-is-an-evil-twin-attack/) is a spoofing cyberattack that works by tricking users into connecting to a fake Wi-Fi access point that mimics a legitimate network. Once a user is connected to an “evil twin” network, hackers can access everything from their network traffic to private login credentials.

Evil twin attacks get their name from their ability to imitate legitimate Wi-Fi networks to the extent that they are indistinguishable from one another. This type of attack is particularly dangerous because it can be nearly impossible to identify.  
  
This project includes the methods used for an Evil Twin attack, as well as a defense mechanism to detect and defend from such an attack.

### Prerequisite:
- A laptop with a NIC that can enter [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode)
- Or a external wifi adapter that can be conncted and enable [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode)
- Libraries and tools used: Python 3.8+, Scapy, airmon-ng, hostapd, iptables, gnome-terminal, apache2, net-tools 

*Note** - This program was written and tested on Ubuntu 20.04, but should work on most Linux machines.  
  


### To ensure that all necessary packages are installed:
`bash setup.sh`

### To start the main program:
`sudo python start.py`   
  
  
**From there the program will guide you in the terminal console. **

<img src="https://user-images.githubusercontent.com/57404551/168290083-9ff0fa9a-956a-4304-b8c6-af0a1e2c5518.png" alt="Start screen" height= 150 width=400 />

  
  
  

### Evil Twin Attack:
The steps taken to initate the attack are:
  - Get the necessary details of the adapter and its interface name.
  - Scan for all available access points in the area.
  - Select an AP from the list of discovered access points.
  - Scan for users connected to the selected AP.
  - Select a victim to perform the attack on from the list of scanned users connected to the chosen AP.
  - Deauthenticate the victim: disconnect him from his wifi connection.
  - Create and activate the fake access point that will be a "twin" of the original access point that the user was connected to.
  - Wait for the user to reconnect to our fake AP, and our [captive portal](https://en.wikipedia.org/wiki/Captive_portal) will ask him for his email and password.
  - After getting their sensitive info, we need to deactivate the fake AP to avoid detection.  
 
 
  
### Evil Twin Defense:
Here we choose to try and defend ourselves from an Evil Twin attack for a certain time (as needed).
This tool will receive details including the mac address of the current wifi network we are connected to.
If it detects a certain number of [deauthentication packets](https://en.wikipedia.org/wiki/Network_packet), it warns us (the user) and after a certain threshold of these packets counted, it will reset our computers network manager to prevent the deauthentication process.


### Captive Portal:
I chose for my [captive portal](https://en.wikipedia.org/wiki/Captive_portal) to be more of a joke than to try and scam someone such as creating a clone of a popular social media or bank website or even wifi credentials.
But just to capture the idea of my captive portal that opens when the victim connects to my fake access point.
Once the users clicks submit, the info is then saved to the "passwords.txt" file.
  
<img src="https://user-images.githubusercontent.com/57404551/168290449-924e5cff-2c87-4233-9e45-19d7aca30d85.png" alt="Start screen" height= 200 width=400 />
 
