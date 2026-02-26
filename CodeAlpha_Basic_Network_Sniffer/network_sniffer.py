#!/usr/bin/env python3
"""
Basic Network Sniffer - Educational Tool
Captures and displays network packets with filtering options
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sys

# Global variables
packet_count = 0
log_file = None

def display_banner():
    """Display application banner"""
    print("=" * 70)
    print(" " * 20 + "BASIC NETWORK SNIFFER")
    print("=" * 70)
    print()

def get_user_input():
    """Get filter and logging preferences from user"""
    print("Select Protocol Filter:")
    print("  1. TCP only")
    print("  2. UDP only")
    print("  3. ICMP only")
    print("  4. All packets")
    print()
    
    choice = input("Enter choice (1-4): ").strip()
    
    # Map choice to BPF filter
    filter_map = {
        '1': 'tcp',
        '2': 'udp',
        '3': 'icmp',
        '4': ''
    }
    bpf_filter = filter_map.get(choice, '')
    
    print()
    log_enabled = input("Do you want to save packets to a log file?\nEnter (y/n): ").strip().lower() == 'y'
    
    print()
    count_input = input("How many packets to capture?\nEnter number (0 for unlimited): ").strip()
    packet_limit = int(count_input) if count_input.isdigit() else 0
    
    return bpf_filter, log_enabled, packet_limit

def open_log_file():
    """Create and open log file with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"packet_log_{timestamp}.txt"
    print()
    print(f"Packets will be saved to: {filename}")
    return open(filename, 'w')

def packet_callback(packet):
    """Process each captured packet"""
    global packet_count, log_file
    
    # Only process packets with IP layer
    if not packet.haslayer(IP):
        return
    
    packet_count += 1
    
    # Extract packet information
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Determine protocol
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"
    
    # Extract payload preview
    payload_preview = "No Payload"
    if packet.haslayer(TCP) and packet[TCP].payload:
        try:
            payload_data = bytes(packet[TCP].payload)
            payload_preview = payload_data.decode('utf-8', errors='ignore')[:50]
        except:
            payload_preview = str(packet[TCP].payload)[:50]
    elif packet.haslayer(UDP) and packet[UDP].payload:
        try:
            payload_data = bytes(packet[UDP].payload)
            payload_preview = payload_data.decode('utf-8', errors='ignore')[:50]
        except:
            payload_preview = str(packet[UDP].payload)[:50]
    
    # Format output
    output = f"""
[Packet #{packet_count}] - {timestamp}
{"-" * 70}
  Source IP      : {src_ip}
  Destination IP : {dst_ip}
  Protocol       : {protocol}
  Packet Size    : {packet_size} bytes
  Payload Preview: {payload_preview}
{"-" * 70}
"""
    
    # Display to terminal
    print(output)
    
    # Write to log file if enabled
    if log_file:
        log_file.write(output)
        log_file.flush()

def start_sniffing(bpf_filter, packet_limit):
    """Start packet capture"""
    print()
    print("=" * 70)
    print("Starting packet capture... (Press Ctrl+C to stop)")
    print("=" * 70)
    
    try:
        if packet_limit > 0:
            sniff(filter=bpf_filter, prn=packet_callback, count=packet_limit, store=False)
        else:
            sniff(filter=bpf_filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n")
        print("=" * 70)
        print(f"Capture stopped. Total packets captured: {packet_count}")
        print("=" * 70)

def main():
    """Main function"""
    global log_file
    
    try:
        # Step 1: Display banner
        display_banner()
        
        # Step 2: Get user preferences
        bpf_filter, log_enabled, packet_limit = get_user_input()
        
        # Step 3: Open log file if needed
        if log_enabled:
            log_file = open_log_file()
        
        # Step 4: Start packet capture
        start_sniffing(bpf_filter, packet_limit)
        
    except PermissionError:
        print("\n[ERROR] Permission denied. Run with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        sys.exit(1)
    finally:
        # Step 5: Cleanup
        if log_file:
            log_file.close()
            print(f"\nLog saved to: {log_file.name}")

if __name__ == "__main__":
    main()
