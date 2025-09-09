# Network Sniffer
#
# Author: Burhan Shah
# Version: 2.0.1
# Description: A Python-based network sniffer to capture, analyze, and
#              geolocate network packets for educational purposes.
#
# Disclaimer: This tool is for educational use only. Unauthorized sniffing
#             of networks is illegal. Use this tool responsibly and only on
#             networks you have explicit permission to analyze.

import sys
import time
import threading
import itertools
from queue import Queue, Empty

# Third-party libraries
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, DNS
    import requests
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"Error: Missing required library. Please run 'pip install {e.name}'.")
    sys.exit(1)


# --- Global Variables & Configuration ---

# Initialize Colorama for cross-platform colored text
init(autoreset=True)

# A thread-safe queue to hold packets from Scapy's sniffing thread
PACKET_QUEUE = Queue()
# A cache to store geolocation data to avoid redundant API calls
GEOLOCATION_CACHE = {}
# An event to signal the animation and sniffing threads to stop
STOP_EVENT = threading.Event()

# --- Geolocation Logic ---

def get_geo_location(ip_address):
    """
    Fetches geolocation information for a given IP address using the ip-api.com API.
    It uses a local cache to avoid repeated requests for the same IP.
    """
    if ip_address in GEOLOCATION_CACHE:
        return GEOLOCATION_CACHE[ip_address]

    if ip_address.startswith(('10.', '192.168.')) or ip_address == '127.0.0.1' or '172.' in ip_address:
        return "Private/Local Network"

    try:
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data['status'] == 'success':
            location_info = (
                f"{data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}, "
                f"{data.get('country', 'N/A')} (ISP: {data.get('isp', 'N/A')})"
            )
            GEOLOCATION_CACHE[ip_address] = location_info
            return location_info
        else:
            return "Geolocation Failed"
    except requests.exceptions.RequestException:
        return "API Request Error"
    except Exception:
        return "Geolocation Error"

# --- Animation & Display Logic ---

def animate_waiting():
    """
    Displays a spinning cursor animation while waiting for packets.
    This runs in a separate thread.
    """
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    while not STOP_EVENT.is_set():
        if PACKET_QUEUE.empty():
            sys.stdout.write(f"\r{Fore.CYAN}[*] Waiting for packets... {next(spinner)}")
            sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 40 + '\r') # Clean up the line on exit
    sys.stdout.flush()

def print_packet_details(packet):
    """
    Dissects and prints packet information with colors.
    """
    if not packet.haslayer(IP):
        return

    # Clear the animation line before printing packet info
    sys.stdout.write('\r' + ' ' * 40 + '\r')
    sys.stdout.flush()
    
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    geo_location = get_geo_location(src_ip)

    eth_layer = packet.getlayer(Ether)
    src_mac = eth_layer.src
    dst_mac = eth_layer.dst

    print("\n" + Fore.WHITE + Style.BRIGHT + "="*80)
    print(f"[*] Packet Captured at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.GREEN}[+] Ethernet Frame: {src_mac} -> {Fore.YELLOW}{dst_mac}")
    print(f"{Fore.GREEN}[+] IP Packet: {src_ip} -> {Fore.YELLOW}{dst_ip}")
    print(f"{Fore.MAGENTA}    \\-> Source Geolocation: {geo_location}")

    protocol = ""
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        protocol = "TCP"
        # Correctly iterate over flags in Scapy 3+
        flags = "".join([flag for flag in "FSRPAUEC" if tcp_layer.flags & flag])
        print(f"{Fore.CYAN}[+] {protocol} Segment: Port {tcp_layer.sport} -> Port {tcp_layer.dport}")
        print(f"{Fore.CYAN}    \\-> Flags: [{flags}] | Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack}")

    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        protocol = "UDP"
        print(f"{Fore.CYAN}[+] {protocol} Datagram: Port {udp_layer.sport} -> Port {udp_layer.dport}")
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode()
                print(f"{Fore.CYAN}    \\-> DNS Query for: {query_name}")

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        try:
            payload = packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload
            if payload:
                payload_data = bytes(payload).decode('utf-8', errors='replace')
                print(f"{Style.DIM}[+] Payload Data (first 100 bytes):\n---BEGIN---\n{payload_data[:100]}\n---END---")
        except Exception:
            pass # Silently ignore payload decoding errors
            
    print(Fore.WHITE + Style.BRIGHT + "="*80)

# --- Core Sniffing Logic ---

def packet_callback(packet):
    """
    This function is called by Scapy for each captured packet.
    It simply puts the packet into our thread-safe queue.
    """
    PACKET_QUEUE.put(packet)

def main():
    """
    Main function to start the sniffer and its threads.
    """
    print(Fore.WHITE + Style.BRIGHT + "=" * 35)
    print(Fore.WHITE + Style.BRIGHT + "   ShahBytes Animated Sniffer")
    print(Fore.WHITE + Style.BRIGHT + "=" * 35)
    
    # Start the animation thread
    animation_thread = threading.Thread(target=animate_waiting, daemon=True)
    animation_thread.start()

    # Start the sniffing thread
    sniff_thread = threading.Thread(
        target=lambda: sniff(prn=packet_callback, store=0, stop_filter=lambda p: STOP_EVENT.is_set()),
        daemon=True
    )
    
    try:
        sniff_thread.start()
        # Main thread's job is to process packets from the queue
        while not STOP_EVENT.is_set():
            try:
                # Wait for a packet to arrive in the queue
                packet = PACKET_QUEUE.get(timeout=1)
                print_packet_details(packet)
                PACKET_QUEUE.task_done()
                # --- ADDED DELAY ---
                time.sleep(1) # Pause for 3 seconds after printing
            except Empty:
                # This allows the loop to continue and check STOP_EVENT
                continue
    except PermissionError:
        STOP_EVENT.set()
        print(f"\n{Fore.RED}[ERROR] Permission denied. Please run with sudo or as Administrator.")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Sniffing stopped by user. Exiting...")
        STOP_EVENT.set()
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] An unexpected error occurred: {e}")
        STOP_EVENT.set()
    
    # Wait for threads to finish cleanly
    sniff_thread.join(timeout=2)
    animation_thread.join(timeout=1)
    print(f"{Fore.GREEN}Shutdown complete.")

if __name__ == "__main__":
    main()
