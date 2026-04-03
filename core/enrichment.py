import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def enrich_ip(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        res = requests.get(url, headers=headers, timeout=10)

        if res.status_code != 200:
            return {}

        data = res.json()["data"]["attributes"]

        return {
            "country": data.get("country"),
            "reputation": data.get("reputation"),
            "malicious": data["last_analysis_stats"].get("malicious", 0)
        }

    except:
        return {}
