import subprocess
import time
import os
from datetime import datetime
from pymongo import MongoClient

# -----------------------------
# MongoDB Connection
# -----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# Absolute Path Setup
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALERT_LOG = os.path.join(BASE_DIR, "logs", "alerts.txt")
FIREWALL_LOG = os.path.join(BASE_DIR, "logs", "firewall.log")

# Ensure log files exist
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
open(ALERT_LOG, "a").close()
open(FIREWALL_LOG, "a").close()

# -----------------------------
# Logging Functions
# -----------------------------
def alert(message):
    with open(ALERT_LOG, "a") as f:
        f.write(f"{datetime.now()} | ALERT: {message}\n")


def log_firewall(message):
    with open(FIREWALL_LOG, "a") as f:
        f.write(f"{datetime.now()} | {message}\n")

# -----------------------------
# Block IP
# -----------------------------
def block_ip(ip):

    try:
        # Check if already blocked
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stderr=subprocess.PIPE
        )

        if check.returncode == 0:
            return  # already blocked

        # Block IP
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

        # Update DB
        collection.update_one(
            {"ip": ip},
            {"$set": {"status": "active"}}
        )

        print("Blocked:", ip)

        alert(f"Blocked malicious IP {ip}")
        log_firewall(f"Blocked {ip}")

    except Exception as e:
        print("Error blocking IP:", ip, e)

# -----------------------------
# Unblock IP (Rollback)
# -----------------------------
def unblock_ip(ip):

    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

        collection.update_one(
            {"ip": ip},
            {"$set": {"status": "inactive"}}
        )

        print("Unblocked:", ip)

        alert(f"Unblocked IP {ip}")
        log_firewall(f"Unblocked {ip}")

    except Exception as e:
        print("Error unblocking IP:", ip, e)

# -----------------------------
# Policy Enforcer Loop
# -----------------------------
def enforce_policy():

    while True:

        threats = collection.find({
            "risk_score": {"$gte": 80},
            "status": {"$ne": "active"}
        }).limit(50)   # prevent overload

        for threat in threats:

            ip = threat["ip"]

            block_ip(ip)

        time.sleep(60)

# -----------------------------
# Main Entry
# -----------------------------
if __name__ == "__main__":

    print("Starting firewall policy enforcer...")

    enforce_policy()
