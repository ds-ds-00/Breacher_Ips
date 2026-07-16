import time
from collections import defaultdict

class ICMPFloodDetector:
    def __init__(self, threshold=50, window=1.0):
        
        self.threshold = threshold
        self.window = window
        self.history = defaultdict(list)

    def evaluate(self, parsed_data):
        
        if parsed_data["proto"] == "ICMP" and parsed_data["icmp_type"] == 8:
            src_ip = parsed_data["src_ip"]
            now = time.time()

        
            self.history[src_ip] = [t for t in self.history[src_ip] if now - t <= self.window]
            self.history[src_ip].append(now)

            if len(self.history[src_ip]) > self.threshold:
                return {
                    "type": "ICMP Flood",
                    "src_ip": src_ip,
                    "details": f"Sent {len(self.history[src_ip])} ping requests in {self.window}s (Threshold: {self.threshold})"
                }
        return None