from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP, TCP


def packet_callback(pkt):
    global first_pkt
    ip_packet = IP(pkt.get_payload())
    # Check if the destination IP address is in the network 192.168.1.0/24
    if ip_packet.dst.startswith('192.168.52.130') and ip_packet.haslayer("Raw") and ip_packet[TCP].dport == 5555:
        # Modify the payload
        new_payload = b"xyz\n"
        del ip_packet[TCP].chksum
        del ip_packet[IP].chksum
        del ip_packet[IP].len
        ip_packet[Raw].load = new_payload
        pkt.set_payload(bytes(ip_packet))
    pkt.accept()


# Create a netfilter queue object with queue number 1
queue = NetfilterQueue()
queue.bind(1, packet_callback)
try:
    # Start the netfilter queue and wait for packets
    queue.run()
except KeyboardInterrupt:
    # If the user interrupts the program with Ctrl+C, stop the netfilter queue
    queue.unbind()

# sudo iptables --flush
# sudo iptables -L -n -v --line-numbers
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
# sudo cat  /proc/sys/net/ipv4/ip_forward
# sudo echo 1 >  /proc/sys/net/ipv4/ip_forward
