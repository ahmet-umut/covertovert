from CovertChannelBase import CovertChannelBase

from scapy.all import *
import threading

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name):
        binary_message = self.generate_random_binary_message()

        terminate = False
        # Asynchronously poll for user input to terminate the message
        def poll_input():
            nonlocal terminate
            input()
            terminate = True

        # Start the polling thread
        threading.Thread(target=poll_input).start()
        
        # Send the message
        for bit in binary_message:
            # Set the CD flag based on the bit
            cd_flag = (bit == "1")

            # Send the packet
            super().send(packet=over(cd_flag))

            # Print the bit
            print(bit, end="", flush=True)

            if terminate:
                break

        
    def receive(self, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        # Receive the message
        message = ""
        while True:
            # Receive the packet
            # Start sniffing for DNS packets (UDP port 53)
            packet = sniff(filter="udp and port 53", prn=packet_callback, store=0)

            """  # Check if the packet is empty
            if not packet:
                break

            # Get the CD flag from the packet
            cd_flag = packet[DNS].cd

            # Add the bit to the message
            message += "1" if cd_flag else "0"

            # Print packet information
            packet.show() """

        self.log_message("", log_file_name)
def over(cd_flag):
    # Create the DNS query with the CD flag
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
        cd=cd_flag,  # CD flag (set based on the boolean variable)
        qdcount=1,  # One question
        ancount=0,  # No answers
        nscount=0,  # No authority records
        arcount=0,  # No additional records
        qd=DNSQR(qname="", qtype="A")  # Question: A record for www.example.com
    )

    # Create the minimal UDP packet (8 bytes)
    udp_packet = UDP(sport=RandShort(), dport=53) / dns_query

    # Create the minimal IP packet (20 bytes)
    ip_packet = IP(dst="receiver") / udp_packet

    return ip_packet

# Function to process and extract the CD flag from DNS packets
def packet_callback(packet):
    # Check if the packet has the necessary layers (IP, UDP, and DNS)
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
        # Extract the DNS layer
        dns_layer = packet[DNS]
        
        # Check if the packet is a DNS query (not a response)
        if dns_layer.qr == 0:  # Query
            cd_flag = dns_layer.cd  # Extract the CD flag
            #print the bit
            print("1" if cd_flag else "0", end="", flush=True)
