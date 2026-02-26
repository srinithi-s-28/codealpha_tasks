#!/usr/bin/env python3
from scapy.all import *

print("Testing ICMP capture...")
print("Run 'ping 8.8.8.8' in another terminal NOW")
print("-" * 50)

def show_packet(pkt):
    if ICMP in pkt:
        print(f"✓ ICMP: {pkt[IP].src} -> {pkt[IP].dst}")
    elif TCP in pkt:
        print(f"✓ TCP: {pkt[IP].src} -> {pkt[IP].dst}")
    elif UDP in pkt:
        print(f"✓ UDP: {pkt[IP].src} -> {pkt[IP].dst}")

try:
    sniff(prn=show_packet, count=20, timeout=30)
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    print("\nSOLUTION:")
    print("1. Download Npcap: https://npcap.com/dist/npcap-1.79.exe")
    print("2. Install with 'WinPcap API-compatible Mode' checked")
    print("3. Restart computer")
    print("4. Run this script as Administrator")

input("\nPress Enter to exit...")
