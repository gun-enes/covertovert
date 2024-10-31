from scapy.all import *

def receive_icmp(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        print("Received ICMP packet with TTL=1:")
        packet.show()

if __name__ == "__main__":
    sniff(filter="icmp", prn=receive_icmp)

