# Python Network Packet Sniffer

This Python script demonstrates a simple network packet sniffer that captures and analyzes Ethernet frames, IPv4 packets, ICMP, TCP, and UDP segments.

## Features

- Captures packets using raw sockets and processes them based on Ethernet frame headers.
- Parses IPv4 packets to extract source and destination addresses, TTL, and protocol.
- Handles ICMP packets to display type, code, and checksum.
- Analyzes TCP segments for source/destination ports, sequence/acknowledgment numbers, and flags.
- Parses UDP segments to show source/destination ports and length.



## Usage

To use the packet sniffer:

1. Ensure you have sufficient privileges to capture packets (often requires running as root/administrator).
2. Run the script using Python 3.x:
   ```bash
   python3 Packet-Sniffer.py
3. Monitor the output as packets are captured and processed.

## Understanding Ethernet Frames

Ethernet frames are the fundamental units of data transmission in Ethernet networks. Each frame includes:

- **Destination MAC Address**: The MAC address of the device intended to receive the frame.
- **Source MAC Address**: The MAC address of the device sending the frame.
- **EtherType/Protocol**: Specifies the protocol of the encapsulated payload (e.g., IPv4, ARP).

## Packet Sniffing Approach

### Raw Socket Creation

The script creates a raw socket (`socket.AF_PACKET`) to capture all incoming packets at the Ethernet layer.

### Ethernet Frame Parsing

Upon receiving a packet, it parses the Ethernet frame to extract MAC addresses and EtherType/Protocol.

### Layer 2 Filtering

The script filters packets based on the EtherType/Protocol field:
- If it's IPv4 (`0x0800`), the script continues to parse the IPv4 headers.
- Further processing depends on the protocol (ICMP, TCP, UDP) identified in the IPv4 header.

### Protocol Handling

- **IPv4 Parsing**: Extracts IPv4 headers such as version, header length, TTL, and protocol.
- **ICMP Handling**: Displays ICMP type, code, and checksum.
- **TCP Handling**: Analyzes TCP segments for source/destination ports, sequence/acknowledgment numbers, and flags.
- **UDP Handling**: Shows UDP source/destination ports and length.

## Dependencies

- Python 3.x
- `socket`, `struct`, and `textwrap` modules (standard library)

## Notes

- This script is intended for educational purposes and may require modification for specific network environments.
- Handle with care as raw packet capturing and processing can have security implications.
   
   
