
from scapy.all import *

# Packet callback function
def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"Packet from {ip_src} to {ip_dst}")
            if packet.haslayer(TCP):
                print(f"  TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
        else:
            print("Non-IP packet received")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniffing function
def start_sniffing(interface="eth0", packet_count=10):
    print(f"Starting to sniff on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    start_sniffing(interface="eth0", packet_count=10)
