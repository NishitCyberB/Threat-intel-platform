from flask import Flask, render_template
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

    threats = list(collection.find().sort("date_added", -1).limit(10))

    return render_template(
        "dashboard.html",
        total=total,
        sources=sources,
        threats=threats
    )


if __name__ == "__main__":
    app.run(port=5000)
