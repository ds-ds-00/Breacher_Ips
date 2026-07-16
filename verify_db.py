import sqlite3
import time

def check_alerts():
    print("\n--- Scanning BreacherIPS Database Logs ---")
    try:
        conn = sqlite3.connect("database/breacherips.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, attack_type, src_ip, details FROM alerts ORDER BY id DESC LIMIT 5;")
        rows = cursor.fetchall()
        
        if not rows:
            print("[*] Database connection successful, but no alerts triggered yet.")
        for row in rows:
            print(f"ID: {row[0]} | Time: {row[1]} | Threat: {row[2]} | IP: {row[3]}\n └── Details: {row[4]}")
            
        conn.close()
    except sqlite3.Error as e:
        print(f"[!] Error accessing SQLite Database: {e}")

if __name__ == "__main__":
    check_alerts()