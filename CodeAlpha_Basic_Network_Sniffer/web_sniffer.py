#!/usr/bin/env python3
"""
Web-Based Network Sniffer - Educational Tool
Access via web browser at http://localhost:5000
"""

from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import queue

app = Flask(__name__)

# Global variables
packet_queue = queue.Queue()
is_sniffing = False
sniff_thread = None
packet_list = []

def packet_callback(packet):
    """Process captured packets"""
    if not packet.haslayer(IP):
        return
    
    ip_layer = packet[IP]
    
    # Determine protocol
    if packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    else:
        protocol = "Other"
    
    # Extract payload
    payload = "No Payload"
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        payload = f"Type: {icmp_type}, Code: {icmp_code}"
    elif packet.haslayer(TCP) and packet[TCP].payload:
        try:
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')[:50]
        except:
            payload = "Binary Data"
    elif packet.haslayer(UDP) and packet[UDP].payload:
        try:
            payload = bytes(packet[UDP].payload).decode('utf-8', errors='ignore')[:50]
        except:
            payload = "Binary Data"
    
    packet_info = {
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'protocol': protocol,
        'size': len(packet),
        'payload': payload
    }
    
    packet_list.append(packet_info)
    packet_queue.put(packet_info)

def start_sniffing_thread(protocol_filter, count):
    """Background thread for packet capture"""
    global is_sniffing
    try:
        # Use iface parameter for better Windows compatibility
        if protocol_filter:
            if count > 0:
                sniff(filter=protocol_filter, prn=packet_callback, count=count, store=False, timeout=1)
            else:
                sniff(filter=protocol_filter, prn=packet_callback, store=False, timeout=1)
        else:
            # No filter - capture all
            if count > 0:
                sniff(prn=packet_callback, count=count, store=False, timeout=1)
            else:
                sniff(prn=packet_callback, store=False, timeout=1)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        is_sniffing = False

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global is_sniffing, sniff_thread, packet_list
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': 'Already capturing'})
    
    data = request.json
    protocol = data.get('protocol', '')
    count = int(data.get('count', 0))
    
    # Fix ICMP filter for Windows
    if protocol == 'icmp':
        protocol = 'icmp or icmp6'
    
    packet_list.clear()
    is_sniffing = True
    
    sniff_thread = threading.Thread(target=start_sniffing_thread, args=(protocol, count))
    sniff_thread.daemon = True
    sniff_thread.start()
    
    return jsonify({'status': 'success', 'message': 'Capture started'})

@app.route('/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global is_sniffing
    is_sniffing = False
    return jsonify({'status': 'success', 'message': 'Capture stopped'})

@app.route('/packets')
def get_packets():
    """Get captured packets"""
    return jsonify({'packets': packet_list, 'is_sniffing': is_sniffing})

@app.route('/clear', methods=['POST'])
def clear_packets():
    """Clear packet list"""
    global packet_list
    packet_list.clear()
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    print("=" * 70)
    print(" " * 15 + "NETWORK SNIFFER - WEB INTERFACE")
    print("=" * 70)
    print("\n🌐 Open your browser and go to: http://localhost:5000")
    print("\n⚠️  Make sure to run as Administrator!\n")
    print("=" * 70)
    app.run(debug=False, host='0.0.0.0', port=5000)
