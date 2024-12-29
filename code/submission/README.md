# README.md

## Overview

This project implements a covert storage channel using protocol field manipulation. Specifically, it exploits the CD (Checking Disabled) flag field in DNS packets to encode and transmit information covertly. The goal is to maximize the covert channel capacity by efficiently transmitting information using this manipulation technique. The implementation adheres to the specifications provided in the assignment and aims to achieve a high data transmission rate (bits per second).

## Features

- *Protocol Field Manipulation:* Uses the CD flag in DNS packets for encoding and decoding bits of information.
- *Custom Encoding and Decoding:* Supports configurable encoding and decoding dictionaries for flexible bit transmission.
- *Random Binary Message Generation:* Dynamically generates a random binary message of specified length.
- *Logging:* Logs binary representations as strings of "0" and "1"'s (characters) transmitted and received messages for verification and analysis.
- *Performance Measurement:* Calculates and reports the covert channel capacity in bits per second in the send() function call.

## Code Description

The main functionality is implemented in the MyCovertChannel class, which is derived from CovertChannelBase. The two core methods are:

### send

This function transmits a binary message using a covert channel. The key steps are:

1. Generate a binary message.
2. Use the provided encoding dictionary to map "biti" bits of the message to "bito" bits. Details about this parameter will be explained.
3. Send the mapped bits bit by bit as DNS packets, modifying the CD flag to convey the information.
4. Measure the time taken for sender to send the message and calculate the covert channel capacity.

### receive

This function listens for incoming packets and decodes the received bits into the original binary message. The steps are:

1. Construct a decoding dictionary based on the provided encoding dictionary. The provided dictionary, thus, should be generated correctly.
2. Capture packets using the sniff function and extract the CD flag values.
3. Decode the received bits and reconstruct the message.
4. Log the reconstructed message (in binary string representation format) and terminate when last 8 bits correspond to "." and the received bit count is a multiply of 8.

## How to Run

### Prerequisites

- Python 3.
- Scapy library
- A network environment with permission to capture and send DNS packets.

### Usage

1. Clone the repository and navigate to the project directory.
2. Ensure the configuration parameters are correctly set in by running the `rand.py` code to generate `config.json`. However, the given config.json already satisfies the constraints.
3. Use the provided Makefile commands for running and testing:
	 - To receive data:
		 ```bash
		 make receive
		 ```
		 Command will be run at first to capture the received packets.

	 - To send data:
		 ```bash
		 make send
		 ```
		 To send the covert channel packets.

	 - To compare the logs of the send and receive processes:
		 ```bash
		 make compare
		 ```
		 Command will be run to check whether the message transfer is successfully completed or not.

4. Generate documentation using:
	 ```bash
	 make documentation
	 ```


## Parameters

- *biti* = the input bit-size of the encoding dictionary. Must be a divisor of the total bit-length of the message.
- *bito* = the output bit-size of possible encodings of each biti-bits. This has no limitation except that (obviously) bito>=biti: It is not possible to decode a bit string from a uniformly random distribution into a smaller length.
- *Encoding Dictionary:* Each biti-bit string must map to one or more unique bito-bit strings. Ensure that biti <= bito.
- *Network Environment:* The script is designed for UDP over port 53 (DNS). Ensure proper network permissions.

## Example Output

### Sender

````
Sender is running!
Message string:  V.
Message binary:  0101011000101110
Time elapsed:  0.4233067035675049 seconds
bits/sec: 37.79765325036596
````


### Receiver


````
decoding: { '11': '00', '01': '01', '00': '10', '10': '11' }
Received message: V.
````


## Performance

Performance is directly related to biti/bito for obvious reasons. You can try the code yourself, however, let me give you some samples. (Message length is always 8 characters.)

#### sample 1
{'0': {'0'}, '1': {'1'}}  biti=1 bito=1	-> 34 bits/s
#### sample 2
{'00': {'10'}, '01': {'00'}, '10': {'01'}, '11': {'11'}}	biti=2	bito=2	-> 38 bits/s
#### sample 3
{'00': {'001'}, '01': {'100', '000'}, '10': {'011', '111', '110'}, '11': {'101', '010'}}	biti=2 bito=3	-> 26 bits/s
#### sample 4
{'0': {'10', '01'}, '1': {'00', '11'}}	biti=1 bito=2	-> 19 bits/s
#### sample 5
{'0': {'101', '100', '011', '110', '111'}, '1': {'001', '000', '010'}}	biti=1 bito=3	-> 13 bits/s
#### sample 6
{'0': {'1111', '0110', '0111', '0101', '0100', '0000', '0010', '1001', '0011'}, '1': {'1101', '0001', '1110', '1000', '1010', '1100', '1011'}}	biti=1 bito=4	-> 9 bits/s

### comment about examples
As you can see, the bitrate is proportional to the biti/bito.

### explanation of the dictionary value
Let me go over the dictionary parameter (encoder dictionary) in the sample 3 to better convey what it is used for:
{'00': {'001'}, '01': {'100', '000'}, '10': {'011', '111', '110'}, '11': {'101', '010'}}

00->{001} means that whenever 00 occurs in the input message, 001 is sent.
01->{100,000} means that %50 of the time when a 01 occurs, it is sent as 100 and %50 it is sent as 000.
10->{011,111,110} means that there is 1/3 chance 10 is encoded as each element in the set.
...

So, the resulting decoder will reverse map all elements in the sets to the corresponding values. So for this case:
001->00, 100->01, 000->01, 011->10, 111->10, 110->10, 101->11, 010->11

I hope the explanation is clear. The rand.py (given in the .tar.gz file also) is used to create a encoder in the config.json given desired biti and bito values. While the encoder'd be enough to infer biti and bito, we believe explicitly stating those primal parameters is more reasonable.