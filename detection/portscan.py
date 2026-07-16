import time
from collections import defaultdict

class PortScanDetector:
    def __init__(self, threshold=20, window=5.0):
        
        self.threshold = threshold
        self.window = window
        
        self.history = defaultdict(dict)

    def evaluate(self, parsed_data):
        
        if parsed_data["proto"] not in ["TCP", "UDP"]:
            return None

        src_ip = parsed_data["src_ip"]
        dport = parsed_data["dport"]
        now = time.time()

        if dport is not None:
        
            self.history[src_ip] = {p: t for p, t in self.history[src_ip].items() if now - t <= self.window}
            
        
            self.history[src_ip][dport] = now

        
            if len(self.history[src_ip]) > self.threshold:
                return {
                    "type": "Port Scan",
                    "src_ip": src_ip,
                    "details": f"Scanned {len(self.history[src_ip])} unique ports within {self.window}s."
                }
        return None