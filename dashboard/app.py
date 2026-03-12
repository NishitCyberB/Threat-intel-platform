from flask import Flask
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]


@app.route("/")
def dashboard():

    threats = list(collection.find())

    total = len(threats)

    response = f"Total threats: {total}\n\n"

    for t in threats[:10]:

        response += f"{t['ip']} | {t['source']} | risk {t['risk_score']}\n"

    return "<pre>" + response + "</pre>"


if __name__ == "__main__":

    app.run(port=5000)
