from flask import Flask, render_template
from pymongo import MongoClient
import os

app = Flask(__name__)

# -----------------------------
# MongoDB Connection
# -----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# Paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(BASE_DIR, "logs", "alerts.txt")

# Ensure logs folder exists
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

# -----------------------------
# Dashboard Route
# -----------------------------
@app.route("/")
def dashboard():

    try:
        total = collection.count_documents({})
        active = collection.count_documents({"status": "active"})
        inactive = collection.count_documents({"status": "inactive"})
        new = collection.count_documents({"status": "new"})

        sources = list(collection.aggregate([
            {"$group": {"_id": "$source", "count": {"$sum": 1}}}
        ]))

        threats = list(collection.find().sort("date_added", -1).limit(10))

        # 🔥 Blocked IPs (IMPORTANT)
        blocked_ips = list(collection.find({"status": "active"}).limit(20))

    except Exception as e:
        print("DB Error:", e)
        total = active = inactive = new = 0
        sources = threats = blocked_ips = []

    # 🔥 Alerts
    alerts = []
    if os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "r") as f:
            alerts = f.readlines()[-10:]

    # 🔥 Firewall Logs
    firewall_logs = []
    FIREWALL_LOG = os.path.join(BASE_DIR, "logs", "firewall.log")

    if os.path.exists(FIREWALL_LOG):
        with open(FIREWALL_LOG, "r") as f:
            firewall_logs = f.readlines()[-10:]

    return render_template(
        "dashboard.html",
        total=total,
        active=active,
        inactive=inactive,
        new=new,
        sources=sources,
        threats=threats,
        alerts=alerts,
        firewall_logs=firewall_logs,
        blocked_ips=blocked_ips
    )

    # -----------------------------
    # Read Alerts
    # -----------------------------
    alerts = []

    if os.path.exists(ALERT_LOG):
        try:
            with open(ALERT_LOG, "r") as f:
                alerts = f.readlines()[-10:]
        except:
            alerts = []

    # -----------------------------
    # Render
    # -----------------------------
    return render_template(
        "dashboard.html",
        total=total,
        active=active,
        inactive=inactive,
        new=new,
        sources=sources,
        threats=threats,
        alerts=alerts
    )

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(port=5000, debug=True)
