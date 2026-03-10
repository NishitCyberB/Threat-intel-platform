import subprocess
from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]


def block_ip(ip):

    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        subprocess.run(command, check=True)
        print("Blocked IP:", ip)
    except Exception as e:
        print("Error blocking IP:", e)


def enforce_policy():

    threats = collection.find()

    for threat in threats:
        ip = threat["ip"]
        block_ip(ip)


if __name__ == "__main__":
    print("Starting firewall policy enforcement...")
    enforce_policy()
