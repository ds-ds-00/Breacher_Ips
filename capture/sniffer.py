import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from capture.packet_queue import packet_queue

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    packet_queue.put_packet(packet)


def start_sniffer():
    print("[*] Starting Scapy Packet Sniffer... Press Ctrl+C to stop.")
    try:
        sniff(iface="lo",prn=process_packet, store=0)
    except PermissionError:
        print("[!] Error: You must run this script with administrative (root/sudo) privileges.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")
        sys.exit(0)

if __name__ == "__main__":
    start_sniffer()
