from pymongo import MongoClient
from datetime import datetime, timezone

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intel"]
collection = db["malicious_ips"]

def insert_ip(ip, source):

    risk_score = 80

    if source == "spamhaus":
        risk_score = 90

    data = {
        "ip": ip,
        "source": source,
        "risk_score": risk_score,
        "date_added": datetime.now(timezone.utc)
    }

avoid duplicates
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
