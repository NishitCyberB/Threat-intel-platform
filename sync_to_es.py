import os
from datetime import datetime, timezone
from pymongo import MongoClient
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

# ========================= CONFIG =========================
# Use 'mongo' and 'elasticsearch' service names for Docker networking
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/threat_intel")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")

mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = mongo_client.get_default_database()

# FIX: Force Version 8 compatibility to stop the 'found 9' BadRequestError
es = Elasticsearch(
    ES_HOST,
    headers={
        "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
        "Content-Type": "application/json"
    },
    request_timeout=30
)

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
        # Check if index exists using the client
        if not es.indices.exists(index=INDEX_NAME):
            # Using specific arguments for compatibility across v7/v8/v9 clients
            es.indices.create(index=INDEX_NAME, mappings=mapping["mappings"])
            print(f"✅ Created Elasticsearch index: {INDEX_NAME}")
        else:
            print(f"✅ Index {INDEX_NAME} already exists")
    except Exception as e:
        print(f"Index creation error: {e}")

# ========================= SYNC LOGIC =========================
def sync_mongo_to_es():
    create_es_index()
    
    inserted = 0
    failed = 0
    
    print(f"🔄 Fetching records from MongoDB...")
    cursor = db.iocs.find()
    
    for doc in cursor:
        # 1. Handle Timestamp Formatting
        ts = doc.get("timestamp")
        if isinstance(ts, datetime):
            # Ensure it is ISO formatted for Elasticsearch
            ts_iso = ts.replace(tzinfo=timezone.utc).isoformat()
        else:
            ts_iso = datetime.now(timezone.utc).isoformat()

        # 2. Build the Document
        es_doc = {
            "ioc_type": doc.get("type", "unknown"),
            "value": doc.get("value"),
            "source": doc.get("source"),
            "risk_score": doc.get("risk_score", 50),
            "severity": doc.get("severity", "medium"),
            "description": doc.get("description", ""),
            "tags": doc.get("tags", []),
            "timestamp": ts_iso,
            "feed_name": doc.get("feed_name", "unknown")
        }
        
        # 3. Index into ES
        try:
            es.index(
                index=INDEX_NAME,
                id=str(doc.get("value")),
                document=es_doc
            )
            inserted += 1
        except Exception:
            failed += 1
            # We skip printing every error to keep the console readable
            continue

    # Refresh the index to make sure the count is accurate immediately
    try:
        es.indices.refresh(index=INDEX_NAME)
        final_count = es.count(index=INDEX_NAME)["count"]
        print(f"✅ Sync completed! Successfully indexed: {inserted}")
        print(f"❌ Failed records: {failed}")
        print(f"📊 Total documents now in ES: {final_count}")
    except Exception as e:
        print(f"Final status check failed: {e}")

if __name__ == "__main__":
    print("🔄 Starting MongoDB → Elasticsearch sync...")
    print(f"Connecting to Mongo: {MONGO_URI}")
    print(f"Connecting to ES: {ES_HOST}")
    
    try:
        sync_mongo_to_es()
    except Exception as e:
        print(f"Critical Sync Error: {e}")
        
    print("🎉 Sync process finished!")
