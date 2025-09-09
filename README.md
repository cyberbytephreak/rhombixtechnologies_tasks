Network Sniffer
Author: Burhan Shah
Version: 2.0.2
Date: September 1, 2025
Description
This is a Python-based network sniffing tool designed for educational purposes. It captures network packets in real-time, analyzes their layers (Ethernet, IP, TCP, UDP, DNS), and attempts to geolocate the source IP address using the ip-api.com service. The tool features a user-friendly, color-coded console output and a waiting animation to enhance the user experience.
Disclaimer
This tool is for educational use only. Unauthorized sniffing of networks is illegal. Use this tool responsibly and only on networks for which you have explicit permission to analyze. The author is not responsible for any misuse of this tool.
Features
● Live Packet Capture: Sniffs the network for live IPv4 packets.
● Detailed Packet Analysis: Displays information for Ethernet, IP, TCP, and UDP layers.
● DNS Query Display: Shows DNS queries being made on the network.
● IP Geolocation: Provides location information (City, Region, Country) and the ISP for public source IP addresses.
● Color-Coded Output: Uses colorama for a readable and organized display of packet details.
● Multi-threaded Design: Utilizes separate threads for sniffing and UI animations to ensure a non-blocking, responsive experience.
● Payload Preview: Shows the first 100 bytes of the packet's payload data, if available.
Requirements
● Python 3.x
● The following Python libraries:
○ scapy
○ requests
○ colorama
Installation
1. Clone the repository or download the network_sniffer.py file.
Install the required libraries using pip: pip install scapy requests colorama
2.
Usage
This tool requires elevated privileges to capture network packets.
On Linux or macOS: sudo python3 network_sniffer.py
●
On Windows: Open Command Prompt or PowerShell as an Administrator and run: python network_sniffer.py
●
Once running, the tool will immediately start listening for packets. To stop the sniffer, press Ctrl+C.
How It Works
The application operates on three main threads:
1. Sniffing Thread: A dedicated thread runs Scapy's sniff function, which captures packets from the network. Each captured packet is placed into a thread-safe queue.
2. Animation Thread: This thread displays a simple spinning cursor animation in the console, providing visual feedback that the program is actively waiting for packets.
3. Main Thread: The main thread continuously checks the packet queue. When a packet is available, it retrieves it, processes it through the print_packet_details function, and displays the analyzed information. It then pauses for a second before processing the next packet.
