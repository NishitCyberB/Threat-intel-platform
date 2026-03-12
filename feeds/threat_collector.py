import requests
from pymongo import MongoClient
from datetime import datetime, timezone

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# Multiple OSINT feeds
FEEDS = {
    "abuse_ch": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt"
}


def get_risk_score(source):

    if source == "spamhaus":
        return 90
    elif source == "abuse_ch":
        return 80
    else:
        return 50


def insert_ip(ip, source):

    if collection.find_one({"ip": ip}):
        return

    data = {
        "ip": ip,
        "source": source,
        "risk_score": get_risk_score(source),
        "date_added": datetime.now(timezone.utc)
    }

    collection.insert_one(data)

    print("Inserted:", ip, "| Source:", source)


def fetch_feed(source, url):

    try:

        response = requests.get(url)

        for line in response.text.split("\n"):

            if line.startswith("#") or line.strip() == "":
                continue

            ip = line.split()[0]

            insert_ip(ip, source)

    except Exception as e:

        print("Error fetching", source, e)


def collect_all_feeds():

    print("Collecting threat feeds...")

    for source, url in FEEDS.items():

        print("Fetching:", source)

        fetch_feed(source, url)


if __name__ == "__main__":

    collect_all_feeds()
