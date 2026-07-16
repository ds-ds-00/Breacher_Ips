import queue
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IPS.Queue")

class PacketQueueManager:
    def __init__(self, max_size=10000):
     
        self._queue = queue.Queue(maxsize=max_size)
        logger.info(f"Packet Queue initialized with a max size of {max_size} packets.")

    def put_packet(self, packet):
       
        try:
            
            self._queue.put_nowait(packet)
        except queue.Full:
            
            logger.warning("[!] Packet queue is FULL. Dropping incoming packet to maintain sniffer stability.")

    def get_packet(self, timeout=1.0):
        
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def task_done(self):
        
        self._queue.task_done()

    def get_size(self):
        
        return self._queue.qsize()


packet_queue = PacketQueueManager(max_size=20000)