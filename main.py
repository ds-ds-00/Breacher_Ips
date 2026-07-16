import threading
import time
import sys
import logging

from colorama import Fore, Back, Style, init
from capture.sniffer import start_sniffer
from parser.extractor import start_extractor
from detection.engine import DetectionEngine

from prevention.firewall import FirewallController
from prevention.whitelist import whitelist
from database.db import db_manager

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: Fore.LIGHTBLACK_EX + self.fmt + Style.RESET_ALL,
            logging.INFO: Fore.GREEN + self.fmt + Style.RESET_ALL,
            logging.WARNING: Fore.RED + self.fmt + Style.RESET_ALL,
            logging.ERROR: Fore.YELLOW + self.fmt + Style.RESET_ALL,
            logging.CRITICAL: Back.RED + Fore.WHITE + self.fmt + Style.RESET_ALL
        }

    def format(self, record):
        if hasattr(record, "is_banner") and record.is_banner:
            return Fore.CYAN + record.msg + Style.RESET_ALL
            
        log_fmt = self.FORMATS.get(record.levelno, Fore.WHITE + self.fmt + Style.RESET_ALL)
        
        if "[DB_LOGGED]" in record.msg:
            log_fmt = log_fmt.replace(record.msg, Fore.CYAN + record.msg + Style.RESET_ALL)
        elif "Bypass rule matched" in record.msg:
            log_fmt = log_fmt.replace(record.msg, Fore.LIGHTBLACK_EX + record.msg + Style.RESET_ALL)

        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

if root_logger.hasHandlers():
    root_logger.handlers.clear()

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(ColoredFormatter("%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s"))
root_logger.addHandler(stdout_handler)

logger = logging.getLogger("BreacherIPS.Main")

def main():
    init(autoreset=True)
    
    logger.info("========================================", extra={"is_banner": True})
    logger.info(Style.BRIGHT + "      INITIALIZING BREACHER IPS        ", extra={"is_banner": True})
    logger.info("========================================", extra={"is_banner": True})

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