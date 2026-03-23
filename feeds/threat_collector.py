import requests
from pymongo import MongoClient
from datetime import datetime, timezone
import re
import os

# -----------------------------
# MongoDB connection
# -----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# Absolute log path (IMPORTANT)
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "logs", "threat_log.txt")

# -----------------------------
# Threat Feeds
# -----------------------------
FEEDS = {
    "abuse_ch": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt"
}

# -----------------------------
# IP Validation
# -----------------------------
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

# -----------------------------
# Risk Scoring
# -----------------------------
def calculate_risk(source):

    if source == "spamhaus":
        return 90
    elif source == "abuse_ch":
        return 80
    elif source == "blocklist_de":
        return 75
    else:
        return 50

# -----------------------------
# Logging
# -----------------------------
def log_event(message):

    with open(LOG_PATH, "a") as log:

        timestamp = datetime.now(timezone.utc)

        log.write(f"{timestamp} | {message}\n")

# -----------------------------
# Insert IP
# -----------------------------
def insert_ip(ip, source):

    ip = ip.strip()

    # Skip invalid IP
    if not is_valid_ip(ip):
        return

    # Skip duplicate
    if collection.find_one({"ip": ip}):
        return

    data = {
        "ip": ip,
        "source": source,
        "threat_type": "botnet",
        "risk_score": calculate_risk(source),
        "status": "new",   # IMPORTANT FIX
        "date_added": datetime.now(timezone.utc)
    }

    collection.insert_one(data)

    log_event(f"Inserted threat {ip} from {source}")

# -----------------------------
# Fetch Feed
# -----------------------------
def fetch_feed(source, url):

    try:

        response = requests.get(url, timeout=10)

        count = 0

        for line in response.text.split("\n"):

            if line.startswith("#") or line.strip() == "":
                continue

            ip = line.split()[0]

            insert_ip(ip, source)

            count += 1

            # LIMIT for performance (IMPORTANT)
            if count >= 100:
                break

        print(f"{source}: collected {count} IPs")

    except Exception as e:

        print("Error fetching", source, e)

# -----------------------------
# Main Collector
# -----------------------------
def collect_feeds():

    print("Collecting threat intelligence feeds...")

    for source, url in FEEDS.items():

        print("Fetching:", source)

        fetch_feed(source, url)

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":

    collect_feeds()
