import os
import requests
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# === Use Docker service names for inter-container communication ===
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/threat_intel")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database()
COLLECTION = db.iocs

def calculate_risk_score(ioc_type: str, source: str) -> int:
    score = 40
    if "malware" in ioc_type.lower() or "phishing" in ioc_type.lower():
        score += 30
    if "urlhaus" in source.lower():
        score += 25
    if "openphish" in source.lower():
        score += 20
    return min(100, score)

def fetch_urlhaus():
    headers = {"User-Agent": "Mozilla/5.0 (Threat-Intel-Platform)"}
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        urls_list = data.get("urls", []) # URLHaus returns dict with 'urls' key
        for item in urls_list[:300]:
            yield {
                "type": "url",
                "value": item["url"],
                "source": "URLHaus",
                "description": f"Malware URL - {item.get('tags', '')}",
                "tags": item.get("tags", []),
                "feed_name": "URLHaus"
            }
    except Exception as e:
        print(f"URLHaus error: {e}")

def fetch_openphish():
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=15)
        r.raise_for_status()
        for line in r.text.strip().splitlines()[:300]:
            if line.strip():
                yield {
                    "type": "url",
                    "value": line.strip(),
                    "source": "OpenPhish",
                    "description": "Phishing URL",
                    "tags": ["phishing"],
                    "feed_name": "OpenPhish"
                }
    except Exception as e:
        print(f"OpenPhish error: {e}")

def fetch_otx_pulses():
    try:
        # Using the public 'recent' endpoint instead of 'subscribed' to avoid 404/Auth errors
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/recent", timeout=15)
        r.raise_for_status()
        data = r.json()
        for pulse in data.get("results", [])[:50]:
            for ind in pulse.get("indicators", [])[:15]:
                yield {
                    "type": ind.get("type", "unknown").lower(),
                    "value": ind.get("indicator"),
                    "source": "AlienVault OTX",
                    "description": pulse.get("name", "Threat Pulse"),
                    "tags": pulse.get("tags", []),
                    "feed_name": "AlienVault_OTX"
                }
    except Exception as e:
        print(f"OTX error: {e}")

def collect_threats():
    print("🚀 Collecting from 3 OSINT feeds (URLHaus + OpenPhish + AlienVault OTX)...")
    all_iocs = []
    for feed in [fetch_urlhaus, fetch_openphish, fetch_otx_pulses]:
        for ioc in feed():
            all_iocs.append(ioc)

    seen = set()
    inserted = 0
    for ioc in all_iocs:
        key = (ioc["type"], ioc["value"])
        if key in seen: continue
        seen.add(key)

        ioc["risk_score"] = calculate_risk_score(ioc["type"], ioc["source"])
        ioc["severity"] = "high" if ioc["risk_score"] >= 70 else "medium"
        ioc["timestamp"] = datetime.now(timezone.utc)

        COLLECTION.update_one(
            {"type": ioc["type"], "value": ioc["value"]},
            {"$set": ioc},
            upsert=True
        )
        inserted += 1

    print(f"✅ Inserted {inserted} unique IOCs into MongoDB")
    print("🔄 Syncing to Elasticsearch...")
    os.system("python sync_to_es.py")

if __name__ == "__main__":
    collect_threats()
