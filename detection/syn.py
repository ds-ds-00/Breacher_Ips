import time
from collections import defaultdict

class SYNFloodDetector:
    def __init__(self, threshold=100, window=1.0):
        
        self.threshold = threshold
        self.window = window
        
        self.history = defaultdict(list)

    def evaluate(self, parsed_data):
        if parsed_data["proto"] != "TCP" or parsed_data["flags"] is None:
            return None

        
        flags = parsed_data["flags"]
        if "S" in flags and "A" not in flags:
            src_ip = parsed_data["src_ip"]
            now = time.time()

            
            self.history[src_ip] = [t for t in self.history[src_ip] if now - t <= self.window]
            
            
            self.history[src_ip].append(now)

            
            if len(self.history[src_ip]) > self.threshold:
                return {
                    "type": "SYN Flood DoS",
                    "src_ip": src_ip,
                    "details": f"Sent {len(self.history[src_ip])} SYN packets in {self.window}s (Threshold: {self.threshold})"
                }
        return None