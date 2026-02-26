#!/usr/bin/env python3
from scapy.all import *
import sys

print("=" * 70)
print("REAL-TIME PACKET SNIFFER")
print("=" * 70)

choice = input("\n1=TCP  2=UDP  3=ICMP  4=ALL\nChoose: ")
filters = {'1': 'tcp', '2': 'udp', '3': 'icmp', '4': ''}
bpf = filters.get(choice, '')

print(f"\nCapturing {bpf if bpf else 'ALL'} packets...")
print("Press Ctrl+C to stop\n")
print("-" * 70)

count = 0

def show(pkt):
    global count
    if IP in pkt:
        count += 1
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "IP"
        print(f"[{count}] {pkt[IP].src:15} -> {pkt[IP].dst:15} | {proto:5} | {len(pkt):4} bytes")
        sys.stdout.flush()

try:
    sniff(filter=bpf if bpf else None, prn=show)
except KeyboardInterrupt:
    print(f"\n\nTotal: {count} packets")
