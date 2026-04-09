from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from elasticsearch import Elasticsearch
import subprocess
from datetime import datetime   # ← Added for audit logging

load_dotenv()

app = Flask(__name__)
CORS(app)

# Connections
mongo_client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel"))
db = mongo_client.get_default_database()

es = Elasticsearch(os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200"))

# ====================== ROLLBACK ENDPOINT ======================
@app.route('/unblock', methods=['POST'])
def unblock_ip():
    data = request.get_json()
    ip = data.get('ip') or data.get('value')
    if not ip:
        return jsonify({"error": "IP/value is required"}), 400

    try:
        # Safer way - no shell=True (prevents command injection)
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        
        # Mark as unblocked in MongoDB
        db.iocs.update_one({"value": ip}, {"$set": {"blocked": False}})
        
        # === IMMUTABLE AUDIT LOG (Compliance Requirement) ===
        db.audit_log.insert_one({
            "timestamp": datetime.utcnow(),
            "action": "UNBLOCK",
            "ioc_value": ip,
            "reason": "Manual rollback by SOC analyst via API",
            "source": "api_unblock_endpoint",
            "user": "admin"
        })
        # ====================================================
        
        return jsonify({"status": "success", "message": f"{ip} has been unblocked"})
    
    except subprocess.CalledProcessError:
        return jsonify({"error": "Failed to remove iptables rule - IP may not be blocked"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ====================== MAIN DASHBOARD ======================
@app.route('/')
def dashboard():
    # Get data from MongoDB
    iocs = list(db.iocs.find().sort("risk_score", -1).limit(50))
    for ioc in iocs:
        ioc['_id'] = str(ioc['_id'])

    # Get data from Elasticsearch
    try:
        es_data = es.search(index="threat_intelligence", size=50, body={
            "query": {"match_all": {}},
            "sort": [{"risk_score": "desc"}]
        })
        es_iocs = [hit['_source'] for hit in es_data['hits']['hits']]
    except:
        es_iocs = []

    return render_template('dashboard.html',
                         mongo_iocs=iocs,
                         es_iocs=es_iocs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
