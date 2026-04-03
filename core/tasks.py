from core.celery_app import celery
from pymongo import MongoClient
from firewall.policy_enforcer import block_ip
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client["threat_intel"]
collection = db["malicious_ips"]

@celery.task
def enforce_policy_task():

    threats = collection.find({
        "risk_score": {"$gte": 80},
        "status": {"$ne": "active"}
    }).limit(50)

    count = 0

    for threat in threats:
        ip = threat["ip"]
        block_ip(ip)
        count += 1

    return f"Processed {count} threats"
