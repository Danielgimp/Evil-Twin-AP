# WHat is Evil Twin Attack?

An  **evil twin**  is a fraudulent  ("Wi-Fi")  access point that appears to be legitimate but is set up to eavesdrop on wireless communications.The evil twin is the  wireless LAN equivalent of the phising scam cyberattacks.
This type of attack may be used to steal the passwords of unsuspecting users, either by monitoring their connections or by phishing, which involves setting up a fraudulent web site and luring people there.

# What tools were used?

For initiationg the attack (EvilTwin.py)
1. Python (Scappy library) - to send or recieve wireless packets and analyze them.
2. Hostapd (Host access point daemon) is capable of turning normal network interface cards into access points and authentication servers.
3. Dnsmasq provides network infrastructure and services for small networks: DNS, DHCP and network boot.
4. IPtables is a linux firewall program. iptables will monitor inbound and outbound traffic as well as forward traffic.
5. UNIX OS is MENDATORY for this attack to work. (Ubuntu and kali are confirmed to work)
6. Monitor mode capable wireless card is required (can be bought for dirt cheap online)
7. Apache as a web server to host a malicious website.

## How EvilTwin.py works?

1. Run the application in the following way: sudo python EvilTwin.py WLANdapter
Where WLANdapter is your wireless adapter
2. Then the Attack puts a compatible adaper into monitoring under unix.
3. Then search for WLAN beacons (AP's)
4. Send a deauthentication attack to the attacked AP dissconnecting all clients.
5. Set up the cloned network with no credentials forcing all the attacked AP's clients to migrate into the fake AP.
6. Initiate a routing table for all the inbound traffic from the monitoring adapter to the wired connection of the host.This is done so that the attacker could monitor all the traffic passing from the evil twin AP to the internet.
7. Start the DHCP server to let clients connect freely.
8.  Let The clients connect to the DNSmasq server.
9. Sniff The packets routed through the malicious web sites you created as a bait or just monitor all traffic, this is your choise.

## How AntiEvilTwin.py works?

1. Run the application in the following way: sudo python EvilTwin.py WLANdapter
Where WLANdapter is your wireless adapter
2. Then the Attack puts a compatible adaper into monitoring under unix.
3. Then search for WLAN beacons (AP's):
	If the network has no protection - Malicious, otherwise this is a legit network.
