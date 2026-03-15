from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

print("Total threats in database:", collection.count_documents({}))

print("\nThreats by source:\n")

pipeline = [
    {"$group": {"_id": "$source", "count": {"$sum": 1}}}
]

for result in collection.aggregate(pipeline):
    print(result["_id"], "→", result["count"])
