import sqlite3
import os
import logging
from datetime import datetime
from database.models import CREATE_ALERTS_TABLE, CREATE_INDEX_SRC_IP

logger = logging.getLogger("BreacherIPS.Database")

class DatabaseManager:
    def __init__(self, db_path="database/breacherips.db"):
        self.db_path = db_path
        
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(CREATE_ALERTS_TABLE)
                cursor.execute(CREATE_INDEX_SRC_IP)
                conn.commit()
            logger.info(f"Database infrastructure ready at {self.db_path}")
        except sqlite3.Error as e:
            logger.critical(f"Failed to bootstrap database layout: {e}")

    def log_alert(self, alert_dict,status="BLOCKED"):
        
        try:
            local_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO alerts (timestamp,attack_type, src_ip, details,status)
                    VALUES (?, ?, ?, ?, ?)
                """
                cursor.execute(query, (
                    local_now,
                    alert_dict["type"],
                    alert_dict["src_ip"],
                    alert_dict["details"],
                    status
                ))
                conn.commit()
            logger.info(f"[DB_LOGGED] Recorded alert metadata for hostile threat from {alert_dict['src_ip']}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed writing security event telemetry log into SQLite storage: {e}")
            return False


db_manager = DatabaseManager()