from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from pymongo import MongoClient
import json
import os
import time
import secrets
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from functools import wraps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename
import logging


GAME_ID = os.getenv("GAME_ID", "AzxiePanel")

SUCCESS_STATUS = int(os.getenv("SUCCESS_STATUS", "945734"))
MAX_FILE_SIZE = 20 * 1024 * 1024

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    MONGO_USER = os.getenv("MONGO_USER")
    MONGO_PASS = os.getenv("MONGO_PASS")
    MONGO_HOST = os.getenv("MONGO_HOST")

    if MONGO_USER and MONGO_PASS and MONGO_HOST:
        MONGO_URI = f"mongodb+srv://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}/?retryWrites=true&w=majority"
    else:
        raise Exception(
            "❌ MongoDB credentials missing!\n"
            "Set MONGO_URI OR (MONGO_USER + MONGO_PASS + MONGO_HOST) in environment"
        )

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client["azxpanel"]
except Exception as e:
    raise Exception(f"❌ MongoDB connection failed: {e}")

keys_collection = db["keys"]
libraries_collection = db["libraries"]
sessions_collection = db["sessions"]
config_collection = db["config"]


def get_config_value(key, default=None):
    doc = config_collection.find_one({"key": key})
    return doc["value"] if doc else default


AES_KEY_B64 = get_config_value("AES_KEY_B64", "").strip()
SECRET_SALT = get_config_value("SECRET_SALT", "").strip()
ADMIN_PASSWORD = get_config_value("ADMIN_PASSWORD", "").strip()


MAX_LOGS = 50
LOG_TTL_HOURS = 24
SESSION_TTL_MINUTES = 10
SESSION_TTL_SAFE_HOURS = 24

try:
    keys_collection.create_index("key", unique=True, sparse=True)
    libraries_collection.create_index("filename", unique=True, sparse=True)
    sessions_collection.create_index("exp_dt", expireAfterSeconds=0)
    db["audit_logs"].create_index("timestamp", expireAfterSeconds=LOG_TTL_HOURS * 3600)
except Exception as e:
    logging.warning(f"Index creation notice: {e}")

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, resources={r"/api.php": {"origins": "*"}})

AES_KEY = base64.b64decode(AES_KEY_B64)
LIBRARIES_DIR = os.path.join(os.path.dirname(__file__), "AzxLibraries")
os.makedirs(LIBRARIES_DIR, exist_ok=True)


def rate_limit(max_calls=10, time_window=60):
    cache = {}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()

            if ip not in cache:
                cache[ip] = []

            cache[ip] = [t for t in cache[ip] if now - t < time_window]

            if len(cache[ip]) >= max_calls:
                return (
                    jsonify({"success": False, "message": "Rate limit exceeded"}),
                    429,
                )

            cache[ip].append(now)
            return f(*args, **kwargs)

        return decorated

    return decorator


def purge_old_logs():
    try:
        audit_logs = db["audit_logs"]
        cutoff = datetime.now() - timedelta(hours=LOG_TTL_HOURS)
        audit_logs.delete_many({"timestamp": {"$lt": cutoff}})

        total = audit_logs.count_documents({})
        if total >= MAX_LOGS:
            overflow = total - MAX_LOGS + 1
            oldest = list(
                audit_logs.find({}, {"_id": 1}).sort("timestamp", 1).limit(overflow)
            )
            ids_to_delete = [doc["_id"] for doc in oldest]
            audit_logs.delete_many({"_id": {"$in": ids_to_delete}})
    except Exception as e:
        logging.error(f"Failed to purge old logs: {e}")


def log_action(action, key=None, status="success", details=None):
    log_entry = {
        "timestamp": datetime.now(),
        "ip": request.remote_addr,
        "action": action,
        "key": key,
        "status": status,
        "details": details,
    }
    try:
        purge_old_logs()
        db["audit_logs"].insert_one(log_entry)
    except Exception as e:
        logging.error(f"Failed to log action: {e}")


def load_keys():
    try:
        keys = {}
        for doc in keys_collection.find():
            if "key" in doc:
                doc.pop("_id", None)
                keys[doc["key"]] = doc
        return keys
    except Exception as e:
        logging.error(f"Error loading keys: {e}")
        return {}


def save_key(key, data):
    try:
        data["key"] = key
        keys_collection.update_one({"key": key}, {"$set": data}, upsert=True)
    except Exception as e:
        logging.error(f"Error saving key: {e}")


def delete_key(key):
    try:
        keys_collection.delete_one({"key": key})
    except Exception as e:
        logging.error(f"Error deleting key: {e}")


def load_libraries():
    try:
        libs = {}
        for doc in libraries_collection.find():
            if "filename" in doc:
                doc.pop("_id", None)
                libs[doc["filename"]] = doc
        return libs
    except Exception as e:
        logging.error(f"Error loading libraries: {e}")
        return {}


def save_library(filename, data):
    try:
        data["filename"] = filename
        libraries_collection.update_one(
            {"filename": filename}, {"$set": data}, upsert=True
        )
    except Exception as e:
        logging.error(f"Error saving library: {e}")


def delete_library(filename):
    try:
        libraries_collection.delete_one({"filename": filename})
    except Exception as e:
        logging.error(f"Error deleting library: {e}")


def create_session(token, exp_time):
    try:
        exp_datetime = datetime.utcfromtimestamp(exp_time)
        sessions_collection.insert_one(
            {
                "token": token,
                "exp": exp_time,
                "exp_dt": exp_datetime,
                "created": datetime.now(),
            }
        )
    except Exception as e:
        logging.error(f"Error creating session: {e}")


def validate_session(token):
    try:
        now = time.time()
        session = sessions_collection.find_one({"token": token, "exp": {"$gt": now}})
        if session is None:
            sessions_collection.delete_many({"exp": {"$lte": now}})
        return session is not None
    except Exception as e:
        logging.error(f"Error validating session: {e}")
        return False


def hmac_sha256(data, key):
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def aes_256_gcm_encrypt(plaintext, key):

    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]
    return iv, ct, tag


def aes_256_gcm_decrypt(ciphertext, iv, tag, key):

    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(iv, combined, None)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")


def send_enc_payload(data_dict, key):
    json_str = json.dumps(data_dict)
    iv, ciphertext, tag = aes_256_gcm_encrypt(json_str, key)
    combined = iv + tag + ciphertext
    payload_b64 = base64.b64encode(combined).decode("utf-8")
    payload_hmac = hmac_sha256(payload_b64, key)
    return jsonify({"enc": True, "payload": payload_b64, "hmac": payload_hmac})


def send_enc_err(reason, key):
    return send_enc_payload({"status": 0, "reason": reason}, key)


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get("token", "") or request.args.get("token", "")
        if not token:
            return jsonify({"success": False, "message": "Unauthorized"})

        if not validate_session(token):
            return jsonify({"success": False, "message": "Session expired"})

        return f(*args, **kwargs)

    return decorated


@app.route("/api.php", methods=["POST", "GET", "OPTIONS"])
def api_handler():
    if request.method == "OPTIONS":
        return "", 200

    action = request.values.get("action", "").strip()

    handlers = {
        "ping": handle_ping,
        "admin_login": handle_admin_login,
        "generate_keys": handle_generate_keys,
        "list_keys": handle_list_keys,
        "get_stats": handle_get_stats,
        "delete_key": handle_delete_key,
        "reset_hwid": handle_reset_hwid,
        "reset_device_count": handle_reset_device_count,
        "upload_library": handle_upload_library,
        "list_libraries": handle_list_libraries,
        "delete_library": handle_delete_library,
        "download_library": handle_download_library,
        "login": handle_login,
        "connect": handle_connect,
    }

    if action in handlers:
        return handlers[action]()

    return jsonify({"success": False, "message": f"Unknown action: {action}"})


def handle_ping():
    return jsonify({"success": True, "status": "online"})


@rate_limit(max_calls=5, time_window=60)
def handle_admin_login():
    password = request.form.get("password", "")
    safe_key = request.form.get("safe_key", "false").lower() in ("true", "1", "yes")

    if not password:
        return jsonify({"success": False, "message": "Password required"})

    if not hmac.compare_digest(ADMIN_PASSWORD, password):
        log_action("admin_login", status="failed", details="Invalid password")
        return jsonify({"success": False, "message": "Invalid password"})

    token = secrets.token_hex(32)

    if safe_key:
        exp_time = time.time() + SESSION_TTL_SAFE_HOURS * 3600
        session_type = "safe"
    else:
        exp_time = time.time() + SESSION_TTL_MINUTES * 60
        session_type = "standard"

    try:
        create_session(token, exp_time)
        log_action("admin_login", status="success", details=f"session={session_type}")
        return jsonify({"success": True, "token": token, "session_type": session_type})
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"success": False, "message": "Login failed"})


@require_admin
def handle_generate_keys():
    duration = int(request.form.get("duration", 0))
    qty = int(request.form.get("qty", 1))
    qty = max(1, min(100, qty))
    custom_name = request.form.get("custom_name", "").strip()
    max_devices = request.form.get("max_devices", "0").strip()

    try:
        max_devices = int(max_devices) if max_devices else 0
    except:
        max_devices = 0

    if duration > 0:
        expires = (datetime.now() + timedelta(days=duration)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    else:
        expires = None

    new_keys = []
    try:
        keys = load_keys()
        for i in range(qty):
            while True:
                if custom_name:
                    k = custom_name if qty == 1 else f"{custom_name}-{i+1}"
                else:
                    k = f"Azxion-{secrets.token_hex(5).upper()}"

                if k not in keys:
                    break

            key_data = {
                "key": k,
                "status": "unused",
                "hwid": None,
                "expires": expires,
                "max_devices": max_devices if max_devices > 0 else 0,
                "device_count": 0,
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_used": None,
            }
            save_key(k, key_data)
            new_keys.append(k)

        log_action("generate_keys", details=f"Generated {qty} keys")
        return jsonify({"success": True, "keys": new_keys})
    except Exception as e:
        logging.error(f"Generate keys error: {e}")
        return jsonify({"success": False, "message": "Failed to generate keys"})


@require_admin
def handle_list_keys():
    search = request.form.get("search", "").lower()
    filter_status = request.form.get("status", "")

    try:
        query = {}
        if filter_status:
            query["status"] = filter_status

        rows = list(keys_collection.find(query).sort("created", -1).limit(200))

        filtered = []
        for doc in rows:
            if search:
                key = doc.get("key", "")
                note = doc.get("note", "")
                if search not in key.lower() and search not in str(note).lower():
                    continue

            doc.pop("_id", None)
            filtered.append(doc)

        return jsonify({"success": True, "keys": filtered})
    except Exception as e:
        logging.error(f"List keys error: {e}")
        return jsonify({"success": True, "keys": []})


@require_admin
def handle_get_stats():
    try:
        total = keys_collection.count_documents({})
        active = keys_collection.count_documents({"status": "active"})
        unused = keys_collection.count_documents({"status": "unused"})
        expired = keys_collection.count_documents({"status": "expired"})
        banned = keys_collection.count_documents({"status": "banned"})

        return jsonify(
            {
                "success": True,
                "total": total,
                "active": active,
                "used": active + expired,
                "expired": expired,
                "unused": unused,
                "banned": banned,
            }
        )
    except Exception as e:
        logging.error(f"Get stats error: {e}")
        return jsonify(
            {
                "success": True,
                "total": 0,
                "active": 0,
                "used": 0,
                "expired": 0,
                "unused": 0,
                "banned": 0,
            }
        )


@require_admin
def handle_delete_key():
    key = request.form.get("key", "")
    try:
        delete_key(key)
        log_action("delete_key", key=key)
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Delete key error: {e}")
        return jsonify({"success": False, "message": "Failed to delete key"})


@require_admin
def handle_reset_hwid():
    key = request.form.get("key", "")
    try:
        keys_collection.update_one(
            {"key": key}, {"$set": {"hwids": [], "device_count": 0, "status": "unused"}}
        )
        log_action("reset_hwid", key=key)
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Reset HWID error: {e}")
        return jsonify({"success": False, "message": "Failed to reset HWID"})


@require_admin
def handle_reset_device_count():
    key = request.form.get("key", "")
    try:
        # FIX: Clear both hwids list and device_count, reset to unused
        keys_collection.update_one(
            {"key": key},
            {
                "$set": {
                    "device_count": 0,
                    "hwids": [],
                    "hwid": None,
                    "status": "unused",
                    "last_used": None,
                }
            },
        )
        log_action("reset_device_count", key=key)
        return jsonify(
            {"success": True, "message": "Device count and HWIDs reset successfully"}
        )
    except Exception as e:
        logging.error(f"Reset device count error: {e}")
        return jsonify({"success": False, "message": "Failed to reset device count"})


@require_admin
def handle_upload_library():
    if "library_file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"})

    file = request.files["library_file"]
    lib_version = request.form.get("lib_version", "").strip()
    lib_description = request.form.get("lib_description", "").strip()

    if not file or file.filename == "":
        return jsonify({"success": False, "message": "No file selected"})

    if not file.filename.endswith(".so"):
        return jsonify({"success": False, "message": "Only .SO files allowed"})

    if file.content_length and file.content_length > MAX_FILE_SIZE:
        return jsonify({"success": False, "message": "File exceeds 20 MB limit"})

    filename = secure_filename(file.filename)
    filepath = os.path.join(LIBRARIES_DIR, filename)

    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        if file_size > MAX_FILE_SIZE:
            os.remove(filepath)
            return jsonify({"success": False, "message": "File exceeds 20 MB limit"})

        lib_data = {
            "filename": filename,
            "size": file_size,
            "version": lib_version if lib_version else None,
            "description": lib_description if lib_description else None,
            "uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        save_library(filename, lib_data)
        log_action("upload_library", details=filename)
        return jsonify({"success": True, "message": "Library uploaded successfully"})
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        logging.error(f"Upload library error: {e}")
        return jsonify({"success": False, "message": f"Upload failed: {str(e)}"})


@require_admin
def handle_list_libraries():
    search = request.form.get("search", "").lower()

    try:
        query = {}
        if search:
            query["filename"] = {"$regex": search, "$options": "i"}

        rows = list(libraries_collection.find(query).sort("uploaded", -1).limit(200))

        for row in rows:
            row.pop("_id", None)

        return jsonify({"success": True, "libraries": rows})
    except Exception as e:
        logging.error(f"List libraries error: {e}")
        return jsonify({"success": True, "libraries": []})


@require_admin
def handle_delete_library():
    filename = secure_filename(request.form.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    try:
        if os.path.exists(filepath):
            os.remove(filepath)

        delete_library(filename)
        log_action("delete_library", details=filename)
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Delete library error: {e}")
        return jsonify({"success": False, "message": f"Failed to delete: {str(e)}"})


@require_admin
def handle_download_library():
    filename = secure_filename(request.args.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"success": False, "message": "File not found"}), 404

    try:
        log_action("download_library", details=filename)
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        logging.error(f"Download library error: {e}")
        return jsonify({"success": False, "message": f"Download failed: {str(e)}"}), 500


@rate_limit(max_calls=10, time_window=60)
def handle_login():
    user_key = request.form.get("user_key", "")
    if not user_key:
        return jsonify({"success": False, "message": "Key required"})

    try:
        key_doc = keys_collection.find_one({"key": user_key})

        if not key_doc:
            return jsonify({"success": False, "message": "Invalid key"})

        if key_doc.get("status") == "banned":
            return jsonify({"success": False, "message": "Key is banned"})

        if key_doc.get("expires"):
            expiry = datetime.strptime(key_doc["expires"], "%Y-%m-%d %H:%M:%S")
            if expiry < datetime.now():
                keys_collection.update_one(
                    {"key": user_key}, {"$set": {"status": "expired"}}
                )
                return jsonify({"success": False, "message": "Key has expired"})

        if key_doc.get("status") == "expired":
            return jsonify({"success": False, "message": "Key has expired"})

        return jsonify({"success": True, "expiry": key_doc.get("expires", "Lifetime")})
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"success": False, "message": "Login error"})


def handle_connect():
    """
    Multi-device support:
    - Allows a key to be used on multiple different devices
    - Each new device increments device_count
    - Respects max_devices limit
    """
    game = request.form.get("game", "")
    auth = request.form.get("auth", "")
    user_key = request.form.get("user_key", "")
    serial = request.form.get("serial", "")  # HWID - device identifier
    t = request.form.get("t", "0")
    sig = request.form.get("sig", "")

    try:
        t_int = int(t)
    except:
        return send_enc_err("Invalid timestamp", AES_KEY)

    if game != GAME_ID:
        return send_enc_err("Invalid game ID", AES_KEY)

    if abs(time.time() - t_int) > 60:
        return send_enc_err("Timestamp expired", AES_KEY)

    message = f"game={game}&auth={auth}&user_key={user_key}&serial={serial}&t={t}"
    expected_sig = hmac_sha256(message, AES_KEY)

    if not hmac.compare_digest(expected_sig, sig):
        logging.warning(f"Signature mismatch from {request.remote_addr}")
        return send_enc_err("Signature mismatch", AES_KEY)

    try:
        key_doc = keys_collection.find_one({"key": user_key})

        if not key_doc:
            return send_enc_err("Key not found", AES_KEY)

        if key_doc.get("status") == "banned":
            return send_enc_err("Key is banned", AES_KEY)

        if key_doc.get("status") == "expired":
            return send_enc_err("Key has expired", AES_KEY)

        # Check expiration
        if key_doc.get("expires"):
            expiry = datetime.strptime(key_doc["expires"], "%Y-%m-%d %H:%M:%S")
            if expiry < datetime.now():
                keys_collection.update_one(
                    {"key": user_key}, {"$set": {"status": "expired"}}
                )
                return send_enc_err("Key has expired", AES_KEY)

        # MULTI-DEVICE LOGIC FIXED
        # Get list of HWIDs that have used this key
        hwids = key_doc.get("hwids", [])
        if not isinstance(hwids, list):
            # Handle old single-HWID format by converting to list
            old_hwid = key_doc.get("hwid")
            if old_hwid:
                hwids = [old_hwid] if old_hwid else []
            else:
                hwids = []

        max_devices = key_doc.get("max_devices", 0)
        device_count = len(hwids)

        # FIX 1: Check if this device is authorized
        if serial not in hwids:
            # This is a NEW device trying to use the key

            # Check device limit
            if max_devices > 0 and device_count >= max_devices:
                return send_enc_err(
                    f"Device limit exceeded ({device_count}/{max_devices})", AES_KEY
                )

            # Add this device to the list
            hwids.append(serial)

            # Update with new HWID list and increment device count
            update_data = {
                "hwids": hwids,
                "device_count": len(hwids),
                "status": "active",
                "last_used": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            # FIX 2: Also update the legacy hwid field for backward compatibility
            if len(hwids) == 1:
                update_data["hwid"] = serial

            logging.info(
                f"Key {user_key} used on new device. Device count: {len(hwids)}/{max_devices if max_devices > 0 else 'unlimited'}"
            )
        else:
            # Same device using the key again, just update last_used
            update_data = {
                "status": "active",
                "last_used": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        # FIX 3: Ensure device_count is never 0 when key is in use
        if key_doc.get("status") == "unused" and serial in hwids:
            # This is the first time this key is being used
            if len(hwids) == 0:
                hwids = [serial]
                update_data["hwids"] = hwids
                update_data["device_count"] = 1
                update_data["hwid"] = serial

        keys_collection.update_one({"key": user_key}, {"$set": update_data})

        # Generate response
        checked_str = f"{GAME_ID}-{user_key}-{serial}-{auth}-{t}-{SECRET_SALT}"
        checked = hashlib.md5(checked_str.encode("utf-8")).hexdigest()
        token = hashlib.md5(user_key.encode("utf-8")).hexdigest()

        response_data = {
            "status": SUCCESS_STATUS,
            "data": {
                "token": token,
                "rng": int(time.time()),
                "expiredDate": key_doc.get("expires", "Lifetime"),
                "checked": checked,
            },
        }

        return send_enc_payload(response_data, AES_KEY)

    except Exception as e:
        logging.error(f"Connect error: {e}")
        return send_enc_err("Connection error", AES_KEY)


@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/admin")
def dashboard():
    return send_from_directory(".", "admin.html")


@app.route("/<path:filename>")
def serve_files(filename):
    return send_from_directory(".", filename)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("\n" + "=" * 70)
    print("🚀 AZZXION ADMIN PANEL - SECURE BACKEND")
    print("=" * 70)
    print(f"✓ Database: MongoDB (azxpanel)")
    print(f"✓ Admin Password: {'*' * len(ADMIN_PASSWORD)}")
    print(f"✓ Encryption: AES-256-GCM")
    print(f"✓ Game ID: {GAME_ID}")
    print(f"✓ API Endpoint: http://0.0.0.0:5000/api.php")
    print("=" * 70 + "\n")

    app.run(debug=False, host="0.0.0.0", port=5000)
