#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship -- Task 1
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

packet_count = 0


def process_packet(packet):
    """Called once for every packet the sniffer captures."""
    global packet_count
    packet_count += 1

    if not packet.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP)

    ip_layer = packet[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    proto_name = "OTHER"
    ports = ""

    if packet.haslayer(TCP):
        proto_name = "TCP"
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
    elif packet.haslayer(UDP):
        proto_name = "UDP"
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        proto_name = "ICMP"

    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] #{packet_count:04d} {proto_name:5s} "
          f"{src_ip:15s} -> {dst_ip:15s}  {ports}")

    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        preview = payload[:48]
        print(f"          payload ({len(payload)}B): {preview}")


def main():
    print("Starting network sniffer -- press Ctrl+C to stop.\n")
    try:
        # store=False keeps memory flat during long captures
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\nCapture stopped. Total packets analysed: {packet_count}")
    except PermissionError:
        print("Run this script with administrator / root privileges.")


if __name__ == "__main__":
    main()
