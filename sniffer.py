from scapy.all import *
from scapy.layers.inet import TCP, IP


def process_packet(pkt):
    if pkt.haslayer(TCP) and (pkt[TCP].dport == 5555 or pkt[TCP].dport == 60380) and pkt[TCP].payload:
        payload = pkt[TCP].payload.load
        message = payload.decode()
        print(message)


sniff(iface="eth0", prn=process_packet, filter="tcp and port 5555", store=0)
print("exit")


