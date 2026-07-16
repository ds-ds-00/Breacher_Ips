import time
import logging
from scapy.all import IP, TCP, UDP, ICMP, Raw
from capture.packet_queue import packet_queue

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SentinelIPS.Extractor")

def extract_features(packet):
    
    if not packet.haslayer(IP):
        return None

    features = {
        "timestamp": time.time(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "proto": "UNKNOWN",
        "packet_size": len(packet),
        "sport": None,
        "dport": None,
        "flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "payload": ""
    }

    
    if packet.haslayer(TCP):
        features["proto"] = "TCP"
        features["sport"] = packet[TCP].sport
        features["dport"] = packet[TCP].dport
       
        features["flags"] = str(packet[TCP].flags)

    
    elif packet.haslayer(UDP):
        features["proto"] = "UDP"
        features["sport"] = packet[UDP].sport
        features["dport"] = packet[UDP].dport

    
    elif packet.haslayer(ICMP):
        features["proto"] = "ICMP"
        features["icmp_type"] = packet[ICMP].type
        features["icmp_code"] = packet[ICMP].code

    
    if packet.haslayer(Raw):
        try:
            
            decoded = packet[Raw].load.decode('utf-8', errors='ignore').strip()
            if decoded:
                features["payload"] = decoded
        except Exception:
            pass

    return features

def start_extractor(detection_engine_callback=None):
    
    logger.info("Feature Extractor thread started and listening to the packet queue.")
    
    while True:
        packet = packet_queue.get_packet(timeout=1.0)
        
        if packet is not None:
            try:
                parsed_data = extract_features(packet)
                
                if parsed_data and detection_engine_callback:
                    detection_engine_callback(parsed_data)
                    
            except Exception as e:
                logger.error(f"Error extracting features from packet: {e}")
            finally:
                packet_queue.task_done()
        else:
            time.sleep(0.01)