import threading
import time
import sys
import logging

from capture.sniffer import start_sniffer
from parser.extractor import start_extractor
from detection.engine import DetectionEngine

from prevention.firewall import FirewallController
from prevention.whitelist import whitelist
from database.db import db_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("BreacherIPS.Main")

def main():
    logger.info("========================================")
    logger.info("      INITIALIZING BREACHER IPS        ")
    logger.info("========================================")

    fw = FirewallController()
    
    whitelist.add_to_whitelist("127.0.0.1")
    whitelist.add_to_whitelist("192.168.1.0/24") 

    
    engine = DetectionEngine(
        firewall_callback=fw.block_ip,
        db_callback=db_manager.log_alert
    )

    
    extractor_thread = threading.Thread(
        target=start_extractor, 
        args=(engine.process_packet_features,),
        name="ExtractorWorker",
        daemon=True
    )
    
    
    sniffer_thread = threading.Thread(
        target=start_sniffer,
        name="SnifferWorker",
        daemon=True
    )

    
    logger.info("Spinning up execution threads...")
    extractor_thread.start()
    sniffer_thread.start()

    logger.info("[*] BreacherIPS engine is fully operational. Press Ctrl+C to terminate.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n[!] Shutdown signal received. Stopping BreacherIPS cleanly...")
        sys.exit(0)

if __name__ == "__main__":
    main()