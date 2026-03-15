from flask import Flask
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]


@app.route("/")
def dashboard():

    total = collection.count_documents({})

    pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]

    sources = list(collection.aggregate(pipeline))

    output = f"Total Threats: {total}\n\nThreats by Source:\n"

    for s in sources:
        output += f"{s['_id']} → {s['count']}\n"

    return "<pre>" + output + "</pre>"


if __name__ == "__main__":
    app.run(port=5000)
