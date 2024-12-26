from CovertChannelBase import CovertChannelBase

from scapy.all import *
import threading
import time
import os,signal
import random
import array

def poll_input():
    input()
    # Send a sigterm to the process
    os.kill(os.getpid(), signal.SIGTERM)
threading.Thread(target=poll_input).start()

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """

    def send(self, log_file_name, biti, bito, encoding):
        uzunluk = 1
        message = self.generate_random_binary_message(min_length=uzunluk, max_length=uzunluk)
        #self.log_message(message, log_file_name)
        print("encoding: ", encoding)
        print("Message: ", message)

        start_time = time.time()
        encoding = eval(encoding)
        # Take biti bits from the message, send encoding[biti] (bito bits) to the receiver
        for i in range(0, len(message), biti):
            binm = message[i:i+biti]
            #print("binm: ", binm)
            #print("encoding[binm]: ", encoding[binm])
            for bit in random.choice(list(encoding[binm])):
                # Set the CD flag based on the bit
                dns_query.cd = int(bit)
                # Send the packet
                super().send(packet = ipudp / dns_query)
        end_time = time.time()

        print("\nTime elapsed: ", end_time - start_time)
        print(f"bits/sec: {(uzunluk*8)/(end_time - start_time)}")

        
    def receive(self, log_file_name, biti, bito, encoding):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        # Receive the message
        decoding = {}
        for key, value in eval(encoding).items():
            for v in value:
                v = int(v, 2)
                decoding[v] = key

        print(f"decoding: {decoding}\n")

        bits = {}
        i = 0
        def process():
            nonlocal i
            while True:
                if len(bits) > i+bito-1:
                    o=0
                    for j in range(i, i+bito):
                        o = o*2 + bits[j]
                    print(decoding[o], end="", flush=True)
                    i += bito
        threading.Thread(target=process).start()

        j=0
        def caba(packet):
            nonlocal j
            if packet.haslayer(DNS):
                bits[j] = packet[DNS].cd
                j += 1
        while 1:    sniff(filter="udp and port 53", prn=caba, store=0)

        #self.log_message("", log_file_name)

dns_query = DNS(
        id=1,  # Transaction ID
        qr=0,  # Query (not response)
        opcode=0,  # Standard query
        aa=0,  # Authoritative Answer
        tc=0,  # Truncated
        rd=1,  # Recursion Desired
        ra=0,  # Recursion Available
        z=0,  # Reserved (0)
        ad=0,  # Authenticated Data
        cd=False,  # CD flag (set based on the boolean variable)
        qdcount=1,  # One question
        ancount=0,  # No answers
        nscount=0,  # No authority records
        arcount=0,  # No additional records
        qd=DNSQR(qname="", qtype="A")  # Question: A record for www.example.com
    )
udp_packet = UDP(sport=RandShort(), dport=53)
ip_packet = IP(dst="receiver")
ipudp = ip_packet / udp_packet

def over(cd_flag):
    # Create the DNS query with the CD flag
    dns_query.cd = cd_flag
    return ipudp / dns_query

# Function to process and extract the CD flag from DNS packets
def packet_callback(packet, decoding=lambda x:x):
    # Check if the packet has the necessary layers (IP, UDP, and DNS)
    #print("packet_callback")
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
        # Extract the DNS layer
        print(decoding[packet[DNS].cd], end="", flush=True)
        return
        dns_layer = packet[DNS]
        
        # Check if the packet is a DNS query (not a response)
        if dns_layer.qr == 0:  # Query
            cd_flag = dns_layer.cd  # Extract the CD flag
            #print the bit
            print("1" if cd_flag else "0", end="", flush=True)
