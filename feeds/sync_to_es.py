import os
from datetime import datetime
from pymongo import MongoClient
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

# ========================= CONFIG =========================
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")

mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = mongo_client.get_default_database()

es = Elasticsearch(ES_HOST)

INDEX_NAME = "threat_intelligence"

# ========================= CREATE INDEX =========================
def create_es_index():
    mapping = {
        "mappings": {
            "properties": {
                "ioc_type": {"type": "keyword"},
                "value": {"type": "keyword"},
                "source": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "severity": {"type": "keyword"},
                "description": {"type": "text"},
                "tags": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "feed_name": {"type": "keyword"}
            }
        }
    }
    
    try:
        if not es.indices.exists(index=INDEX_NAME):
            es.indices.create(index=INDEX_NAME, body=mapping)
            print(f"✅ Created Elasticsearch index: {INDEX_NAME}")
        else:
            print(f"✅ Index {INDEX_NAME} already exists")
    except Exception as e:
        print(f"Index creation error: {e}")

# ========================= SYNC =========================
def sync_mongo_to_es():
    create_es_index()
    
    inserted = 0
    for doc in db.iocs.find():
        es_doc = {
            "ioc_type": doc.get("type", "unknown"),
            "value": doc.get("value"),
            "source": doc.get("source"),
            "risk_score": doc.get("risk_score", 50),
            "severity": doc.get("severity", "medium"),
            "description": doc.get("description", ""),
            "tags": doc.get("tags", []),
            "timestamp": doc.get("timestamp", datetime.utcnow().isoformat()),
            "feed_name": doc.get("feed_name", "unknown")
        }
        
        try:
            es.index(
                index=INDEX_NAME,
                id=str(doc.get("value")),
                document=es_doc
            )
            inserted += 1
        except Exception as e:
            print(f"Error indexing {doc.get('value')}: {e}")
    
    count = es.count(index=INDEX_NAME)["count"]
    print(f"✅ Sync completed! Total documents in ES: {count}")

if __name__ == "__main__":
    print("🔄 Starting MongoDB → Elasticsearch sync...")
    print(f"Mongo: {MONGO_URI}")
    print(f"ES: {ES_HOST}")
    sync_mongo_to_es()
    print("🎉 Sync finished!")
