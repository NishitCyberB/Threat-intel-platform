from pymongo import MongoClient
from datetime import datetime, timezone
import re
import os

# -----------------------------
# MongoDB Connection
# -----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# Log Path
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../logs/threat_log.txt")

# -----------------------------
# IP Validation
# -----------------------------
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

# -----------------------------
# Logging Function
# -----------------------------
def log_event(message):
    with open(LOG_PATH, "a") as f:
        f.write(f"{datetime.now(timezone.utc)} | {message}\n")

# -----------------------------
# Insert Function
# -----------------------------
def insert_ip(ip, source):

    ip = ip.strip()

    # Validate IP
    if not is_valid_ip(ip):
        print("Invalid IP:", ip)
        return

    # Risk scoring
    risk_score = 80
    if source == "spamhaus":
        risk_score = 90
    elif source == "blocklist_de":
        risk_score = 75

    data = {
        "ip": ip,
        "source": source,
        "risk_score": risk_score,
        "status": "new",   # IMPORTANT
        "date_added": datetime.now(timezone.utc)
    }

    # Avoid duplicates
    if not collection.find_one({"ip": ip}):

        collection.insert_one(data)

        print("Inserted:", ip)

        log_event(f"Inserted {ip} from {source}")

    else:
        print("Already exists:", ip)

# -----------------------------
# Test Run
# -----------------------------
if __name__ == "__main__":

    test_ips = [
        "162.243.103.246",
        "178.62.3.223",
        "invalid_ip_test"
    ]

    for ip in test_ips:
        insert_ip(ip, "abuse_ch")
