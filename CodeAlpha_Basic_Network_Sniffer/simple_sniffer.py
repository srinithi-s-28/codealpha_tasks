#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
from scapy.all import *
from datetime import datetime
import threading

app = Flask(__name__)
packets = []
capturing = False

def capture_packet(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other"
        payload = f"Type:{pkt[ICMP].type} Code:{pkt[ICMP].code}" if ICMP in pkt else "No Payload"
        
        packets.append({
            'time': datetime.now().strftime("%H:%M:%S"),
            'src': pkt[IP].src,
            'dst': pkt[IP].dst,
            'proto': proto,
            'size': len(pkt),
            'payload': payload
        })

def sniff_thread(filter_str):
    global capturing
    while capturing:
        sniff(filter=filter_str if filter_str else None, prn=capture_packet, count=1, timeout=1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    global capturing, packets
    packets.clear()
    capturing = True
    filter_str = request.json.get('protocol', '')
    threading.Thread(target=sniff_thread, args=(filter_str,), daemon=True).start()
    return jsonify({'status': 'ok'})

@app.route('/stop', methods=['POST'])
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'ok'})

@app.route('/packets')
def get_packets():
    return jsonify({'packets': packets, 'capturing': capturing})

@app.route('/clear', methods=['POST'])
def clear():
    global packets
    packets.clear()
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("\n🌐 Open: http://localhost:5000\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
