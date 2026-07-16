import ipaddress
import logging

logger = logging.getLogger("BreacherIPS.Whitelist")

class WhitelistManager:
    def __init__(self):
        
        self.whitelisted_networks = [
            ipaddress.ip_network("127.0.0.1/32"),    
            ipaddress.ip_network("0.0.0.0/8")        
        ]
        
    def add_to_whitelist(self, cidr_str):
        
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if net not in self.whitelisted_networks:
                self.whitelisted_networks.append(net)
                logger.info(f"Added {cidr_str} to safety whitelist.")
        except ValueError:
            logger.error(f"Invalid IP/CIDR string provided to whitelist: {cidr_str}")

    def is_whitelisted(self, ip_str):
        
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.whitelisted_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

whitelist = WhitelistManager()