# README.md

## Overview

This project implements a covert storage channel using protocol field manipulation. Specifically, it exploits the CD (Checking Disabled) flag field in DNS packets to encode and transmit information covertly. The goal is to maximize the covert channel capacity by efficiently transmitting information using this manipulation technique. The implementation adheres to the specifications provided in the assignment and aims to achieve a high data transmission rate (bits per second).

## Features

- *Protocol Field Manipulation:* Uses the CD flag in DNS packets for encoding and decoding bits of information.
- *Custom Encoding and Decoding:* Supports configurable encoding and decoding dictionaries for flexible bit transmission.
- *Random Binary Message Generation:* Dynamically generates a random binary message of specified length.
- *Logging:* Logs transmitted and received messages for verification and analysis.
- *Performance Measurement:* Calculates and reports the covert channel capacity in bits per second.

## Code Description

The main functionality is implemented in the MyCovertChannel class, which is derived from CovertChannelBase. The two core methods are:

### send

This function transmits a binary message using a covert channel. The key steps are:

1. Generate a binary message of length 128 bits.
2. Use the provided encoding dictionary to map biti bits of the message to bito bits.
3. Send the mapped bits bit by bit as DNS packets, modifying the CD flag to convey the information.
4. Measure the time taken to transmit the message and calculate the covert channel capacity.

### receive

This function listens for incoming packets and decodes the received bits into the original binary message. The steps are:

1. Construct a decoding dictionary based on the provided encoding dictionary.
2. Capture packets using the sniff function and extract the CD flag values.
3. Decode the received bits and reconstruct the message.
4. Log the reconstructed message and terminate when the full message is received.

## How to Run

### Prerequisites

- Python 3.
- Scapy library
- A network environment with permission to capture and send DNS packets.

### Usage

1. Clone the repository and navigate to the project directory.
2. Ensure the configuration parameters are correctly set in by running the `rand.py` code to generate `config.json`.
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
   
5. To terminate the process, press any key.

## Parameter Limitations

- *Message Length:* The minimum and maximum message length is set to 16 characters (128 bits).
- *Encoding Dictionary:* Each biti-bit string must map to one or more unique bito-bit strings. Ensure that biti <= bito.
- *Default Configuration:*
  - biti = 2: 2 bits are taken from the message at a time.
  - bito = 2: 2 bits are sent at a time.
  - Encoding dictionary: { '00': {'11'}, '01': {'01'}, '10': {'00'}, '11': {'10'} }
  - Decoding dictionary: { '11': '00', '01': '01', '00': '10', '10': '11' }
- *Network Environment:* The script is designed for UDP over port 53 (DNS). Ensure proper network permissions.

## Measuring Covert Channel Capacity

Follow these steps to measure the covert channel capacity:

1. Generate a binary message of length 128 bits.
2. Start the timer before sending the first packet.
3. Stop the timer after the last packet is sent.
4. Calculate the time difference (in seconds).
5. Use the formula:
   
   Capacity (bits/sec) = 128 / Time (seconds)
   
6. The measured capacity is logged in the console.

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

The covert channel capacity achieved is influenced by the network latency, encoding efficiency, and other environmental factors. Ensure a stable network for optimal performance.

## Notes

- Modify the dst IP address in the script to match the receiver's IP.
- Use proper safety precautions when running the script in a networked environment to avoid unintended disruptions.