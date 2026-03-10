import requests

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

def fetch_threat_feed():
    response = requests.get(FEED_URL)

    threats = []

    for line in response.text.split("\n"):
        if line.startswith("#") or line.strip() == "":
            continue

        threats.append(line.strip())

    return threats


def main():
    print("Fetching threat intelligence feed...")

    threat_ips = fetch_threat_feed()

    print("Total threats collected:", len(threat_ips))

    print("\nSample Threat IPs:")

    for ip in threat_ips[:10]:
        print(ip)


if __name__ == "__main__":
    main()
