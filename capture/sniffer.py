import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from capture.packet_queue import packet_queue

def process_packet(packet):

    # Check if the packet has an IP layer (Layer 3)
    if not packet.haslayer(IP):
        return

    packet_queue.put_packet(packet)

    # src_ip = packet[IP].src
    # dst_ip = packet[IP].dst
    # proto = packet[IP].proto

    # proto_name = "UNKNOWN"
    # if packet.haslayer(TCP): proto_name = "TCP"
    # elif packet.haslayer(UDP): proto_name = "UDP"
    # elif packet.haslayer(ICMP): proto_name = "ICMP"

    # # Base logging format
    # log_msg = f"[{proto_name}] {src_ip} -> {dst_ip}"

    # if packet.haslayer(TCP):
    #     log_msg += f" | Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
    #     log_msg += f" | Flags: {packet[TCP].flags}"

    # elif packet.haslayer(UDP):
    #     log_msg += f" | Ports: {packet[UDP].sport} -> {packet[UDP].dport}"

    # # Extract ICMP details
    # elif packet.haslayer(ICMP):
    #     log_msg += f" | Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

    # print(log_msg)

    # if packet.haslayer(Raw):
    #     payload = packet[Raw].load
    #     try:
    #         # Attempt decoding ASCII text (useful for HTTP, DNS, etc.)
    #         decoded_data = payload.decode('utf-8', errors='ignore').strip()
    #         if decoded_data:
    #             print(f"  └── Payload Data: {decoded_data[:100]}")
    #     except Exception:
    #         pass

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
