import scapy
from scapy.all import IP, ICMP, send

# Implement your ICMP sender here

def send_icmp_packet(destination):
	packet = IP(dst=destination, ttl=1) / ICMP()
	send(packet)

send_icmp_packet("receiver")