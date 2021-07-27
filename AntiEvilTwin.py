import os
import sys
import time

from scapy.layers.dot11 import Dot11Beacon
from scapy.sendrecv import sniff

WifiNetworks = {}
EvilTwinWifiNetworks = {}


def scanEvilAP(pkt):
    if pkt.haslayer(Dot11Beacon):  # Check if the packet has an Wireless information
        if pkt.type == 0 and pkt.subtype == 8:
            # Subtype 8 is a beacon frame is one of the management frames (type=0) in IEEE 802.11 based WLANs.
            # It contains all the information about the network. Beacon frames are transmitted periodically,
            # they serve to announce the presence of a wireless LAN and to synchronise the members of the service set.
            # Beacon frames are transmitted by the access point (AP)

            # Check if there are SSID's in the network
            if not (pkt.info.decode("utf-8") in WifiNetworks):

                # if the SSID is encrypted in any way [OPN,WEP,WPA,WPA2] add them to WifiNetworks
                if not ('OPN' in pkt[Dot11Beacon].network_stats()['crypto']):
                    WifiNetworks[pkt.info.decode("utf-8")] = pkt.addr3

                # If those SSID's do not include any security measurements add them to the EvilTwinWifiNetworks dictionary
                # This is true since in our Evil Twin attack Hostpad initiates an unencrypted Wifi Hotspot
            elif (WifiNetworks[pkt.info.decode(
                    "utf-8")] != pkt.addr3):  # check if the MAC not equals to the ap's mac in the dict
                if 'OPN' in pkt[Dot11Beacon].network_stats()['crypto']:
                    if not (pkt.info.decode("utf-8") in EvilTwinWifiNetworks):
                        print("%s" % (pkt.info.decode("utf-8")))
                        EvilTwinWifiNetworks[pkt.info.decode("utf-8")] = pkt.info.decode("utf-8")

        else:
            pass
    else:
        pass


def makeMonitorMode(adapterName):
    print('Changing %s to Monitoring Mode' % adapterName)
    # First we need to enter into Monitor mode for the given adapter (0.5 of waiting was added to make sure it is not too fast)
    os.system('sudo ifconfig %s down' % adapterName)  # turn off the adapter (software)
    time.sleep(0.5)
    os.system('sudo iwconfig %s mode monitor' % adapterName)  # set into monitoring mode
    time.sleep(0.5)
    os.system('sudo ifconfig %s up' % adapterName)  # turn on the adapter (software)
    time.sleep(0.5)


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

    print("These are the Evil Twin Wifi Acess Points:")
    sniff(prn=scanEvilAP, iface=adapterName, count=5000)  # iface - interface to sniff , prn - function


if __name__ == '_main_':
    main()
