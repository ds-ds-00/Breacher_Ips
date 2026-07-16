import logging
from importlib import import_module

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BreacherIPS.DetectionEngine")

class DetectionEngine:
    def __init__(self, firewall_callback=None, db_callback=None):
       
        self.firewall_callback = firewall_callback
        self.db_callback = db_callback
        
        
        self.detectors = []
        self._load_detectors()

    def _load_detectors(self):
       
        try:
            
            from detection.syn import SYNFloodDetector
            from detection.portscan import PortScanDetector
            from detection.icmp import ICMPFloodDetector
            from detection.bruteforce import BruteForceDetector

            self.detectors.extend([
                SYNFloodDetector(),
                ICMPFloodDetector(),
                PortScanDetector(),
                BruteForceDetector()
            ])
            logger.info(f"Successfully loaded {len(self.detectors)} detection modules into BreacherIPS.")
        except ImportError as e:
            logger.warning(f"Some detection modules could not be pre-loaded yet: {e}")
            logger.info("Engine running in partial mode until detector files are built.")

    def process_packet_features(self, parsed_data):
       
        if not parsed_data:
            return

        for detector in self.detectors:
            try:
                alert = detector.evaluate(parsed_data)
                
                
                if alert:
                    self._trigger_mitigation(alert)
                    
            except Exception as e:
                logger.error(f"Error running detector {detector.__class__.__name__}: {e}")

    def _trigger_mitigation(self, alert):
        
        logger.warning(f"[!!!] ALERT TRIGGERED: {alert['type']} detected from Source IP: {alert['src_ip']}")
        mitigation_status="BLOCKED"

        if self.firewall_callback:
            try:
                success=self.firewall_callback(alert['src_ip'])
                if not success:
                    mitigation_status="WHITELISTED_BYPASS"
            except Exception as e:
                logger.error(f"Failed to execute firewall block: {e}")
                mitigation_status="ERROR_BYPASS"

        if self.db_callback:
            try:
                self.db_callback(alert,status=mitigation_status)
                
            except Exception as e:
                logger.error(f"Failed to log alert to DB: {e}")
                