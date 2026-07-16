import subprocess
import logging
from prevention.whitelist import whitelist

logger = logging.getLogger("BreacherIPS.Firewall")

class FirewallController:
    def __init__(self, chain_name="INPUT"):
        
        self.chain_name = chain_name
        self.active_blocks = set()

    def block_ip(self, src_ip):
        
        if whitelist.is_whitelisted(src_ip):
            logger.info(f"[Firewall] Bypass rule matched. Aborting block on whitelisted IP: {src_ip}")
            return False

        if src_ip in self.active_blocks:
            return False

        try:
            
            cmd = ["iptables", "-I", self.chain_name, "-s", src_ip, "-j", "DROP"]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                self.active_blocks.add(src_ip)
                logger.warning(f"[FW_BLOCKED] Linux netfilter is now dropping all traffic from: {src_ip}")
                return True
            else:
                logger.error(f"iptables execution failed: {result.stderr.strip()}")
                
        except FileNotFoundError:
            logger.error("System error: 'iptables' command utility not found on this machine OS.")
        except Exception as e:
            logger.error(f"Unexpected runtime exception when writing firewall block: {e}")
            
        return False

    def unblock_ip(self, src_ip):
        
        if src_ip not in self.active_blocks:
            return False
            
        try:
            cmd = ["iptables", "-D", self.chain_name, "-s", src_ip, "-j", "DROP"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                self.active_blocks.remove(src_ip)
                logger.info(f"[FW_UNBLOCKED] Removed blocking restriction rule for host: {src_ip}")
                return True
        except Exception as e:
            logger.error(f"Error executing firewall unblock routine: {e}")
        return False