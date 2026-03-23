from firewall.policy_enforcer import unblock_ip
from pymongo import MongoClient
import re

# -----------------------------
# MongoDB Connection
# -----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# IP Validation
# -----------------------------
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

# -----------------------------
# Main Control
# -----------------------------
def main():

    ip = input("Enter IP to unblock: ").strip()

    # Validate IP
    if not is_valid_ip(ip):
        print("❌ Invalid IP format")
        return

    # Check if IP exists
    record = collection.find_one({"ip": ip})

    if not record:
        print("⚠️ IP not found in database")
        return

    # Check status
    if record.get("status") != "active":
        print("⚠️ IP is not currently blocked")
        return

    # Perform unblock
    unblock_ip(ip)

    print("✅ IP successfully unblocked")

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    main()
