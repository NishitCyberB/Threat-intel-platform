import subprocess
import time
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]


def block_ip(ip):

    command = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]

    check = subprocess.run(command, stderr=subprocess.PIPE)

    if check.returncode == 0:
        return

    command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    subprocess.run(command)

    print("Blocked:", ip)


def unblock_ip(ip):

    command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    subprocess.run(command)

    print("Unblocked:", ip)


def enforce_policy():

    while True:

        threats = collection.find({"risk_score": {"$gte": 80}})

        for threat in threats:

            ip = threat["ip"]

            block_ip(ip)

        time.sleep(60)


if __name__ == "__main__":

    print("Starting firewall policy enforcer...")

    enforce_policy()
