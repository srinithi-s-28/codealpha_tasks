# Basic Network Sniffer - Educational Tool

## AIM
To develop a beginner-friendly network packet sniffer using Python and Scapy that captures live network traffic, displays packet information in a clean terminal interface, and provides filtering and logging capabilities for educational purposes.

---

## ALGORITHM

### Step 1: Initialize
- Import required libraries (Scapy, datetime, sys)
- Display application banner
- Initialize global variables (packet counter, log file)

### Step 2: Get User Input
- Prompt user to select protocol filter (TCP/UDP/ICMP/All)
- Ask if packets should be saved to log file
- Get number of packets to capture

### Step 3: Configure Sniffer
- Create BPF (Berkeley Packet Filter) based on user selection
- Open log file if logging is enabled
- Set packet count limit

### Step 4: Capture Packets
- Start Scapy sniff() function with configured filter
- For each captured packet:
  - Check if packet has IP layer
  - Extract: Source IP, Destination IP, Protocol, Size, Payload
  - Format and display information
  - Write to log file if enabled
  - Increment packet counter

### Step 5: Handle Termination
- Catch Ctrl+C interrupt
- Display total packets captured
- Close log file
- Exit gracefully

---

## EXPLANATION

### Key Components:

**1. Scapy Library**
- Powerful Python library for network packet manipulation
- Provides sniff() function to capture live packets
- Supports packet layer analysis (IP, TCP, UDP, ICMP)

**2. Packet Callback Function**
- Called for every captured packet
- Extracts relevant information from packet layers
- Formats and displays data in readable format

**3. Protocol Detection**
- Checks packet layers to identify protocol type
- Uses haslayer() method to detect TCP/UDP/ICMP

**4. Payload Extraction**
- Attempts to decode raw payload as UTF-8 text
- Falls back to hex representation if decode fails
- Shows first 50 characters as preview

**5. BPF Filtering**
- Berkeley Packet Filter syntax for efficient filtering
- Filters packets at kernel level (faster than Python filtering)
- Supports: 'tcp', 'udp', 'icmp', or no filter

**6. Logging Feature**
- Creates timestamped log file
- Writes all packet information to file
- Flushes buffer after each write for real-time logging

---

## SAMPLE OUTPUT

```
======================================================================
                    BASIC NETWORK SNIFFER
======================================================================

Select Protocol Filter:
  1. TCP only
  2. UDP only
  3. ICMP only
  4. All packets

Enter choice (1-4): 1

Do you want to save packets to a log file?
Enter (y/n): y

Packets will be saved to: packet_log_20240115_143022.txt

How many packets to capture?
Enter number (0 for unlimited): 10

======================================================================
Starting packet capture... (Press Ctrl+C to stop)
======================================================================

[Packet #1] - 14:30:25
----------------------------------------------------------------------
  Source IP      : 192.168.1.105
  Destination IP : 142.250.185.46
  Protocol       : TCP
  Packet Size    : 66 bytes
  Payload Preview: No Payload
----------------------------------------------------------------------

[Packet #2] - 14:30:25
----------------------------------------------------------------------
  Source IP      : 142.250.185.46
  Destination IP : 192.168.1.105
  Protocol       : TCP
  Packet Size    : 1514 bytes
  Payload Preview: HTTP/1.1 200 OK Content-Type: text/html; charset=
----------------------------------------------------------------------

[Packet #3] - 14:30:26
----------------------------------------------------------------------
  Source IP      : 192.168.1.105
  Destination IP : 8.8.8.8
  Protocol       : TCP
  Packet Size    : 74 bytes
  Payload Preview: GET /search?q=python HTTP/1.1 Host: www.google.c
----------------------------------------------------------------------

======================================================================
Capture stopped. Total packets captured: 10
======================================================================

Log saved to: packet_log_20240115_143022.txt
```

---

## HOW TO RUN ON KALI LINUX

### Prerequisites Installation:

```bash
# Update system packages
sudo apt update

# Install Python3 and pip (usually pre-installed on Kali)
sudo apt install python3 python3-pip -y

# Install Scapy library
sudo pip3 install scapy
```

### Running the Sniffer:

**Method 1: Direct Execution**
```bash
# Navigate to the project directory
cd ~/Desktop/basic\ network\ sniffer/

# Make the script executable
chmod +x network_sniffer.py

# Run with sudo (required for packet capture)
sudo python3 network_sniffer.py
```

**Method 2: Using Python Interpreter**
```bash
# Run directly with Python
sudo python3 network_sniffer.py
```

### Important Notes:

1. **Root Privileges Required**: Packet sniffing requires root/administrator access
   ```bash
   sudo python3 network_sniffer.py
   ```

2. **Stop Capture**: Press `Ctrl + C` to stop packet capture gracefully

3. **View Log Files**: Log files are saved in the same directory
   ```bash
   cat packet_log_*.txt
   ```

4. **Network Interface**: Scapy automatically selects the default network interface

5. **Firewall**: Ensure firewall doesn't block packet capture
   ```bash
   sudo ufw status
   ```

### Troubleshooting:

**Error: Permission Denied**
```bash
# Solution: Run with sudo
sudo python3 network_sniffer.py
```

**Error: Module 'scapy' not found**
```bash
# Solution: Install Scapy
sudo pip3 install scapy
```

**Error: No packets captured**
```bash
# Solution: Check network interface
ip addr show

# Or generate traffic
ping google.com
```

---

## EDUCATIONAL USE ONLY

**WARNING**: This tool is for educational purposes only. Only use on networks you own or have explicit permission to monitor. Unauthorized packet sniffing is illegal.

### Learning Objectives:
- Understand network packet structure
- Learn about TCP/IP protocols
- Practice Python programming
- Explore network security concepts
- Understand packet filtering techniques

---

## FEATURES

- Live packet capture  
- Protocol filtering (TCP/UDP/ICMP)  
- Clean terminal UI  
- Packet information display  
- Payload preview  
- Log file generation  
- Timestamped entries  
- Graceful shutdown  
- Error handling  

---

## LICENSE

This is an educational project. Use responsibly and ethically.
