from flask import Flask, jsonify, request
from pymongo import MongoClient
from firewall.policy_enforcer import block_ip, unblock_ip
import os
from dotenv import load_dotenv
import jwt
import datetime

# Load env
load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("JWT_SECRET")

# MongoDB
client = MongoClient(os.getenv("MONGO_URI"))
db = client["threat_intel"]
collection = db["malicious_ips"]

# -----------------------------
# LOGIN (GET TOKEN)
# -----------------------------
@app.route("/login", methods=["POST"])
def login():

    data = request.json
    username = data.get("username")
    password = data.get("password")

    # Simple demo auth (replace later)
    if username == "admin" and password == "admin":

        token = jwt.encode({
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"}), 401


# -----------------------------
# AUTH DECORATOR
# -----------------------------
def token_required(f):

    def wrapper(*args, **kwargs):

        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token missing"}), 403

        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 403

        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# -----------------------------
# GET ALL THREATS
# -----------------------------
@app.route("/threats", methods=["GET"])
@token_required
def get_threats():

    threats = list(collection.find({}, {"_id": 0}).limit(100))
    return jsonify(threats)


# -----------------------------
# GET BLOCKED IPS
# -----------------------------
@app.route("/blocked", methods=["GET"])
@token_required
def get_blocked():

    threats = list(collection.find(
        {"status": "active"},
        {"_id": 0}
    ))

    return jsonify(threats)


# -----------------------------
# BLOCK IP
# -----------------------------
@app.route("/block", methods=["POST"])
@token_required
def block():

    ip = request.json.get("ip")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    block_ip(ip)

    return jsonify({"message": f"{ip} blocked"})


# -----------------------------
# UNBLOCK IP
# -----------------------------
@app.route("/unblock", methods=["POST"])
@token_required
def unblock():

    ip = request.json.get("ip")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    unblock_ip(ip)

    return jsonify({"message": f"{ip} unblocked"})


# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.route("/")
def home():
    return jsonify({"status": "Secure API running"})


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(port=5001, debug=True)
