from CovertChannelBase import CovertChannelBase

from scapy.all import *
import threading
import time
import os
import signal
import random

""" def poll_input():
    input()
    # Send a sigterm to the process
    os.kill(os.getpid(), signal.SIGTERM)

threading.Thread(target=poll_input).start() """

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want(e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    def __init__(self):
        """
        We put the module namespace parameters in the constructor of the class
        """
        self.dns_params = {
            "id": 1,
            "qr": 0,
            "opcode": 0,
            "aa": 0,
            "tc": 0,
            "rd": 1,
            "ra": 0,
            "z": 0,
            "ad": 0,
            "cd": False,
            "qdcount": 1,
            "ancount": 0,
            "nscount": 0,
            "arcount": 0
        }
        self.qd_params = {
            "qname": "",
            "qtype": "A"
        }

        self.dns_query = DNS(**self.dns_params, qd=DNSQR(**self.qd_params))

        self.udp_packet = UDP(sport=RandShort(), dport=53)
        self.ip_packet = IP(dst="receiver")
        self.ipudp = self.ip_packet / self.udp_packet

    def send(self, log_file_name, biti, bito, encoding):
        """
        - In this function, you are expected to send the message to the receiver. Because there are many types of covert channels, the sender implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.

        uzunluk is the length of the message to be sent.
        biti is the number of bits to be taken from the message at a time.
        bito is the number of bits to be sent at a time.
        encoding is the string form of encoding dictionary that maps biti-bit strings to a set of bito-bit strings.

        The message is sent by taking biti bits from the message and sending a value in encoding[biti](bito bits) to the receiver bit by bit.
        Every value of encoding dictionary must include at least one bito-bit string. Every bito-bit string must be included in at most one value of encoding dictionary. This implicitly asserts that biti <= bito. The ratio biti/bito determines the efficiency of the covert channel. The higher the ratio, the more efficient the covert channel is . When biti == bito, the covert channel is the most efficient. However, this means every biti sequence is mapped to a unique bito sequence. When biti > 1, I believe that setting these 2 parameters equal will not be problem. Because the mapped sequences are sent bit by bit. Anyway, changing the biti/bito ratio is not a problem. It is just a design choice after all.

        How the encoding dictionary is used: When a biti-bit sequence is encoded, a random element of encoding[biti] is chosen, and sent bit by bit.
        """
        uzunluk = 8
        # message = self.generate_random_binary_message(
        #     min_length=uzunluk, max_length=uzunluk)
        # self.log_message(message, log_file_name)

        # self.generate_random_message(uzunluk, uzunluk)
        message_buff = self.generate_random_message(uzunluk, uzunluk)
        message = self.convert_string_message_to_binary(message_buff)

        print("Message string: ", message_buff)
        print("Message binary: ", message)

        start_time = time.time()
        encoding = eval(encoding)
        # Take biti bits from the message, send encoding[biti] (bito bits) to the receiver
        for i in range(0, len(message), biti):
            binm = message[i:i+biti]
            # print("binm: ", binm)
            # print("encoding[binm]: ", encoding[binm])
            for bit in random.choice(list(encoding[binm])):
                # Set the CD flag based on the bit
                # print(bit)
                self.dns_query.cd = int(bit)
                # Send the packet
                super().send(packet=self.ipudp / self.dns_query)
        end_time = time.time()

        print("\nTime elapsed: ", end_time - start_time)
        print(f"bits/sec: {(uzunluk*8)/(end_time - start_time)}")

        self.log_message(message, log_file_name)

    def receive(self, log_file_name, biti, bito, encoding):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.

        I explained the encoding dictionary in the send function. The encoding dictionary is used to create a decoding dictionary. The decoding dictionary maps bito-bit strings to biti-bit strings. It maps the elements of the values in the encoding dictionary to the keys that correspond to that value (values are sets of strings, remember). After calculating the decoding dictionary, the receiver creates a thread and then starts sniffing the network. Whenever a packet is captured, the bound callback function is called. This callback function quickly appends the CD flag of the packet to the bits list. The thread continously processes the bits list and decodes them into the message. Whenever a '.' is encountered, the receiver logs the message and terminates itself.
        """
        # Receive the message
        decoding = {}
        for key, value in eval(encoding).items():
            for v in value:
                decoding[v] = key

        # print(f"decoding: {decoding}\n")

        message = ""
        message_buff = ""

        bits = []
        i = 0

        running = True
        thread = None

        def process():
            nonlocal i, message, message_buff, running, thread
            while True:
                if len(bits) > i+bito-1:
                    # Extract the bits from the received packets
                    o = "".join(str(bits[i+j]) for j in range(bito))
                    # print(bits)
                    message_buff += self.convert_eight_bits_to_character(
                        decoding[o])
                    print(message_buff, end="", flush=True)
                    message += decoding[o]
                    self.log_message(message, log_file_name)
                    if message.endswith("00101110"):
                        running=False
                        # terminate the thread
                        if thread:
                            thread.join()
                        return
                        os.kill(os.getpid(), signal.SIGTERM)
                    i += bito
        #thread = threading.Thread(target=process).start()

        def caba(packet):
            nonlocal i, message, message_buff, running, thread
            if packet.haslayer(DNS):
                bits.append(packet[DNS].cd)
            if len(bits) > i+bito-1:
                # Extract the bits from the received packets
                o = "".join(str(bits[i+j]) for j in range(bito))
                # print(bits)
                print(decoding[o], end="", flush=True)
                message_buff += self.convert_eight_bits_to_character(
                    decoding[o])
                message += decoding[o]
                self.log_message(message, log_file_name)
                if message.endswith("00101110"):
                    print("\n receiver must finish now.")
                    running=False
                    # terminate the thread
                    return True
                    os.kill(os.getpid(), signal.SIGTERM)
                i += bito
                return 0
        sniff(filter="udp and port 53", store=0, stop_filter=caba)

        print("Message: ", message_buff)
        self.log_message(message, log_file_name)
    def generate_json_file(filename="./code/config.json"):
        # Step 1. Set parameters
        biti, bito = 2, 4
        set_i = list(range(2**biti))        # [0, 1, 2, 3] for biti=2
        set_o = list(range(2**bito))        # [0, 1, 2, 3] for bito=2

        # Shuffle set_o to create a random mapping
        random.shuffle(set_o)

        # Helper function to convert an integer to n-bit binary string
        def fn(x, n): return bin(x)[2:].zfill(n)

        # Step 2. Create the random mapping dict
        # Initialize dict with keys '00', '01', '10', '11'
        dict_mapping = {fn(k, biti): set() for k in range(2**biti)}

        # For each i in set_i, map it to the (shuffled) set_o[i]
        for i in set_i:
            dict_mapping[fn(i, biti)].add(fn(set_o[i], bito))

        # set_o[4:] is empty for 2-bit input/output, but we'll keep the code generic
        setm = set(set_o[2**biti:])  # might be empty for these parameters
        for i in setm:
            dict_mapping[fn(random.choice(set_i), biti)].add(fn(i, bito))

        # Convert sets to strings for JSON (or to lists if you prefer)
        # We'll store the entire dictionary mapping as a string (like the sample).
        dict_mapping_str = str(dict_mapping)

        # Step 3. Create the JSON structure
        json_data = {
            "covert_channel_code": "Replace it with the [Code] of chosen covert channel type seen in ODTUClass.",
            "send": {
                "parameters": {
                    "log_file_name": "sender.log",
                    "biti": biti,
                    "bito": bito,
                    "encoding": dict_mapping_str
                }
            },
            "receive": {
                "parameters": {
                    "log_file_name": "receiver.log",
                    "biti": biti,
                    "bito": bito,
                    "encoding": dict_mapping_str
                }
            }
        }

        # Step 4. Write the JSON to file
        with open(filename, "w") as f:
            json.dump(json_data, f, indent=2)

        print(f"JSON file '{filename}' has been generated!")

