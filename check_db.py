from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

print("Total threats:", collection.count_documents({}))

print("\nActive vs Inactive:\n")

pipeline = [
    {"$group": {"_id": "$status", "count": {"$sum": 1}}}
]

for result in collection.aggregate(pipeline):
    print(result["_id"], "→", result["count"])
