import scapy
from scapy.all import sniff, IP, ICMP, Packet

# Implement your ICMP receiver here

def icmp_packet_callback(packet):
	if IP in packet and ICMP in packet and packet[IP].ttl == 1:
		packet.show()
#sniff(filter="icmp", prn=icmp_packet_callback, store=0)