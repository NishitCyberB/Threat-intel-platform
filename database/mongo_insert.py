from pymongo import MongoClient
from datetime import datetime, timezone

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intel"]
collection = db["malicious_ips"]


def insert_ip(ip):

    data = {
        "ip": ip,
        "source": "abuse_ch",
        "risk_score": 80,
        "date_added": datetime.now(timezone.utc)
    }

    # avoid duplicates
    if not collection.find_one({"ip": ip}):
        collection.insert_one(data)
        print("Inserted:", ip)
    else:
        print("Already exists:", ip)


if __name__ == "__main__":

    test_ips = [
        "162.243.103.246",
        "178.62.3.223"
    ]

    for ip in test_ips:
        insert_ip(ip)
