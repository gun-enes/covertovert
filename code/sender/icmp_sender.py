from scapy.all import *

def send_icmp():
    receiver_ip = "client"
    packet = IP(dst=receiver_ip, ttl=1) / ICMP()
    send(packet)
    print("ICMP packet sent with TTL=1")

if __name__ == "__main__":
    send_icmp()

