#!/usr/bin/env python3
"""
Diagnostic tool to test ICMP capture
"""

from scapy.all import *
import sys

print("=" * 70)
print("ICMP CAPTURE DIAGNOSTIC TEST")
print("=" * 70)
print()

# Test 1: Check if running as admin
try:
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    print(f"✓ Running as Administrator: {is_admin}")
    if not is_admin:
        print("  ⚠️  WARNING: Not running as admin! Run PowerShell as Administrator")
except:
    print("✓ Admin check: Unable to verify")

print()

# Test 2: List network interfaces
print("Available Network Interfaces:")
print("-" * 70)
try:
    ifaces = get_windows_if_list()
    for i, iface in enumerate(ifaces):
        print(f"{i+1}. {iface['name']}")
        print(f"   Description: {iface['description']}")
        print()
except:
    print("Unable to list interfaces")

print()

# Test 3: Try to capture ICMP
print("=" * 70)
print("TESTING ICMP CAPTURE (10 seconds)...")
print("=" * 70)
print("Open another terminal and run: ping 8.8.8.8")
print()

captured = []

def packet_handler(pkt):
    if pkt.haslayer(ICMP):
        captured.append(pkt)
        print(f"✓ ICMP Packet: {pkt[IP].src} -> {pkt[IP].dst}")

try:
    sniff(filter="icmp", prn=packet_handler, timeout=10, store=False)
except Exception as e:
    print(f"✗ Error: {e}")

print()
print("=" * 70)
print(f"Total ICMP packets captured: {len(captured)}")
print("=" * 70)

if len(captured) == 0:
    print()
    print("⚠️  NO ICMP PACKETS CAPTURED!")
    print()
    print("Possible solutions:")
    print("1. Install Npcap from: https://npcap.com/#download")
    print("   - Check 'Install Npcap in WinPcap API-compatible Mode'")
    print("2. Run PowerShell as Administrator")
    print("3. Disable Windows Firewall temporarily")
    print("4. Try running: ping 8.8.8.8 in another terminal")
else:
    print()
    print("✓ ICMP capture is working!")

input("\nPress Enter to exit...")
