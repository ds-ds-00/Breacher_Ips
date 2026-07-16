import time
from collections import defaultdict

class BruteForceDetector:
    def __init__(self, threshold=5, window=10.0):
        
        self.threshold = threshold
        self.window = window
        self.history = defaultdict(list)

        self.fail_signatures = [
            "Login Failed", "Authentication failed", "invalid password", 
            "permission denied", "401 Unauthorized", "wp-login.php"
        ]

    def evaluate(self, parsed_data):
        payload = parsed_data.get("payload", "")
        if not payload:
            return None

        matched = any(sig.lower() in payload.lower() for sig in self.fail_signatures)

        if matched:
            src_ip = parsed_data["src_ip"]
            now = time.time()

            self.history[src_ip] = [t for t in self.history[src_ip] if now - t <= self.window]
            self.history[src_ip].append(now)

            if len(self.history[src_ip]) > self.threshold:
                return {
                    "type": "Brute Force Attempt",
                    "src_ip": src_ip,
                    "details": f"Triggered {len(self.history[src_ip])} authentication failures in {self.window}s."
                }
        return None