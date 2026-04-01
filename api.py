from flask import Flask, jsonify, request
from pymongo import MongoClient
from firewall.policy_enforcer import block_ip, unblock_ip
import os
from dotenv import load_dotenv
import jwt
import datetime
import bcrypt

# 🔥 NEW IMPORTS (Rate Limiting)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# -----------------------------
# Load ENV
# -----------------------------
load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("JWT_SECRET")
MONGO_URI = os.getenv("MONGO_URI")

# -----------------------------
# Rate Limiter (GLOBAL)
# -----------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# -----------------------------
# MongoDB
# -----------------------------
client = MongoClient(MONGO_URI)
db = client["threat_intel"]
collection = db["malicious_ips"]
users_collection = db["users"]

# -----------------------------
# LOGIN (RBAC + RATE LIMIT)
# -----------------------------
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")   # 🔥 protect against brute force
def login():

    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = users_collection.find_one({"username": username})

    if not user:
        return jsonify({"error": "User not found"}), 401

    if not bcrypt.checkpw(password.encode(), user["password"]):
        return jsonify({"error": "Invalid password"}), 401

    token = jwt.encode({
        "user": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token})


# -----------------------------
# AUTH DECORATOR
# -----------------------------
def token_required(f):

    def wrapper(*args, **kwargs):

        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token missing"}), 403

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded
        except:
            return jsonify({"error": "Invalid token"}), 403

        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# -----------------------------
# ROLE DECORATOR
# -----------------------------
def role_required(required_role):

    def decorator(f):

        def wrapper(*args, **kwargs):

            user_role = request.user.get("role")

            if user_role != required_role:
                return jsonify({"error": "Access denied"}), 403

            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper

    return decorator


# -----------------------------
# GET ALL THREATS
# -----------------------------
@app.route("/threats", methods=["GET"])
@token_required
@limiter.limit("30 per minute")
def get_threats():

    threats = list(collection.find({}, {"_id": 0}).limit(100))
    return jsonify(threats)


# -----------------------------
# GET BLOCKED IPS
# -----------------------------
@app.route("/blocked", methods=["GET"])
@token_required
@limiter.limit("30 per minute")
def get_blocked():

    threats = list(collection.find(
        {"status": "active"},
        {"_id": 0}
    ))

    return jsonify(threats)


# -----------------------------
# BLOCK IP (ADMIN ONLY)
# -----------------------------
@app.route("/block", methods=["POST"])
@token_required
@role_required("admin")
@limiter.limit("10 per minute")
def block():

    ip = request.json.get("ip")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    block_ip(ip)

    return jsonify({"message": f"{ip} blocked"})


# -----------------------------
# UNBLOCK IP (ADMIN ONLY)
# -----------------------------
@app.route("/unblock", methods=["POST"])
@token_required
@role_required("admin")
@limiter.limit("10 per minute")
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
    return jsonify({"status": "Secure Threat Intel API running"})


# -----------------------------
# SECURITY HEADERS
# -----------------------------
@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    return response


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(port=5001, debug=True)
