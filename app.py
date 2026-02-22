# app.py - Updated with Library Management System & MongoDB Integration

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import json
import os
import time
import secrets
import hashlib
import hmac
import base64
import random
import string
from datetime import datetime, timedelta
from functools import wraps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct
from werkzeug.utils import secure_filename


# MongoDB Connection
mongo_uri = os.getenv("MONGO_URI")
if mongo_uri:
    client = MongoClient(mongo_uri)
else:
    client = MongoClient("mongodb+srv://azxpanel:azxpanelpasswrd@render.4qwq74m.mongodb.net/?appName=Render")

db = client["azxpanel"]
keys_collection = db["keys"]
libraries_collection = db["libraries"]
sessions_collection = db["sessions"]

# Ensure indexes
keys_collection.create_index("key", unique=True, sparse=True)
sessions_collection.create_index("exp", expireAfterSeconds=0)  # TTL index
libraries_collection.create_index("filename", unique=True, sparse=True)

ADMIN_PASSWORD = "changeme"
LIBRARIES_DIR = os.path.join(os.path.dirname(__file__), "AzxLibraries")
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
AES_KEY_B64 = "ijIe7lzCGmmunuhiZ6I/f97NNBAVlLmhaEsfDZJe8eU="
GAME_ID = "AzxiePanel"
SECRET_SALT = "Nh3Dv2WJ9jxfsbEzqWjRlA4KgFY9VQ8H"
SUCCESS_STATUS = 945734

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

AES_KEY = base64.b64decode(AES_KEY_B64)

os.makedirs(LIBRARIES_DIR, exist_ok=True)


# ========== MongoDB Functions ==========

def load_keys():
    """Load all keys from MongoDB"""
    try:
        keys = {}
        for doc in keys_collection.find():
            if "key" in doc:
                doc_copy = doc.copy()
                doc_copy.pop("_id", None)
                keys[doc["key"]] = doc_copy
        return keys
    except Exception as e:
        print(f"Error loading keys: {e}")
        return {}


def save_keys(keys):
    """Save keys to MongoDB"""
    try:
        for key, data in keys.items():
            data_copy = data.copy()
            data_copy["key"] = key
            keys_collection.update_one(
                {"key": key},
                {"$set": data_copy},
                upsert=True
            )
    except Exception as e:
        print(f"Error saving keys: {e}")


def delete_key_db(key):
    """Delete a key from MongoDB"""
    try:
        keys_collection.delete_one({"key": key})
    except Exception as e:
        print(f"Error deleting key: {e}")


def load_libraries():
    """Load all libraries from MongoDB"""
    try:
        libs = {}
        for doc in libraries_collection.find():
            if "filename" in doc:
                doc_copy = doc.copy()
                doc_copy.pop("_id", None)
                libs[doc["filename"]] = doc_copy
        return libs
    except Exception as e:
        print(f"Error loading libraries: {e}")
        return {}


def save_libraries(libs):
    """Save libraries to MongoDB"""
    try:
        for filename, data in libs.items():
            data_copy = data.copy()
            data_copy["filename"] = filename
            libraries_collection.update_one(
                {"filename": filename},
                {"$set": data_copy},
                upsert=True
            )
    except Exception as e:
        print(f"Error saving libraries: {e}")


def delete_library_db(filename):
    """Delete a library from MongoDB"""
    try:
        libraries_collection.delete_one({"filename": filename})
    except Exception as e:
        print(f"Error deleting library: {e}")


def load_sessions():
    """Load all sessions from MongoDB"""
    try:
        sessions = {}
        current_time = time.time()
        for doc in sessions_collection.find({"exp": {"$gt": current_time}}):
            if "token" in doc:
                doc_copy = doc.copy()
                doc_copy.pop("_id", None)
                sessions[doc["token"]] = doc_copy
        return sessions
    except Exception as e:
        print(f"Error loading sessions: {e}")
        return {}


def save_sessions(sessions):
    """Save sessions to MongoDB"""
    try:
        for token, data in sessions.items():
            data_copy = data.copy()
            data_copy["token"] = token
            sessions_collection.update_one(
                {"token": token},
                {"$set": data_copy},
                upsert=True
            )
    except Exception as e:
        print(f"Error saving sessions: {e}")


def create_session(token, exp_time):
    """Create a new session in MongoDB"""
    try:
        sessions_collection.insert_one({
            "token": token,
            "exp": exp_time,
            "created": datetime.now()
        })
    except Exception as e:
        print(f"Error creating session: {e}")


def delete_session(token):
    """Delete a session from MongoDB"""
    try:
        sessions_collection.delete_one({"token": token})
    except Exception as e:
        print(f"Error deleting session: {e}")


# ========== Original Functions ==========

def make_key(custom_name=""):
    if custom_name:
        return custom_name
    return f"Azxion-{secrets.token_hex(5)}"


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get("token", "") or request.args.get("token", "")
        if not token:
            return jsonify({"success": False, "message": "Unauthorized"})

        try:
            session = sessions_collection.find_one({
                "token": token,
                "exp": {"$gt": time.time()}
            })
            
            if not session:
                return jsonify(
                    {"success": False, "message": "Session expired. Please log in again."}
                )
        except Exception as e:
            print(f"Error checking session: {e}")
            return jsonify({"success": False, "message": "Session error."})

        return f(*args, **kwargs)

    return decorated


def hmac_sha256(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
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


# ========== API Routes ==========

@app.route("/api.php", methods=["POST", "GET", "OPTIONS"])
def api_handler():
    if request.method == "OPTIONS":
        return "", 200

    action = request.values.get("action", "").strip()

    if action == "ping":
        return handle_ping()
    elif action == "admin_login":
        return handle_admin_login()
    elif action == "generate_keys":
        return handle_generate_keys()
    elif action == "list_keys":
        return handle_list_keys()
    elif action == "get_stats":
        return handle_get_stats()
    elif action == "delete_key":
        return handle_delete_key()
    elif action == "reset_hwid":
        return handle_reset_hwid()
    elif action == "upload_library":
        return handle_upload_library()
    elif action == "list_libraries":
        return handle_list_libraries()
    elif action == "delete_library":
        return handle_delete_library()
    elif action == "download_library":
        return handle_download_library()
    elif action == "login":
        return handle_login()
    elif action == "connect":
        return handle_connect()
    else:
        return jsonify({"success": False, "message": f"Unknown action: '{action}'"})


def handle_ping():
    return jsonify({"success": True, "status": "online"})


def handle_admin_login():
    password = request.form.get("password", "")
    if not password:
        return jsonify({"success": False, "message": "Password required."})

    if not hmac.compare_digest(ADMIN_PASSWORD, password):
        return jsonify({"success": False, "message": "Invalid password."})

    token = secrets.token_hex(32)
    current_time = time.time()
    exp_time = current_time + 7200  # 2 hours

    try:
        create_session(token, exp_time)
        return jsonify({"success": True, "token": token})
    except Exception as e:
        print(f"Error creating session: {e}")
        return jsonify({"success": False, "message": "Failed to create session."})


@require_admin
def handle_generate_keys():
    duration = int(request.form.get("duration", 0))
    qty = int(request.form.get("qty", 1))
    qty = max(1, min(100, qty))
    note = request.form.get("note", "")
    custom_name = request.form.get("custom_name", "").strip()

    if duration > 0:
        expires = (datetime.now() + timedelta(days=duration)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    else:
        expires = None

    keys = load_keys()
    new_keys = []

    for i in range(qty):
        if custom_name:
            k = custom_name if qty == 1 else f"{custom_name}-{i+1}"
            if k in keys:
                continue
        else:
            while True:
                k = make_key()
                if k not in keys:
                    break

        keys[k] = {
            "key": k,
            "status": "unused",
            "hwid": None,
            "expires": expires,
            "note": note if note else None,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_used": None,
        }
        new_keys.append(k)

    save_keys(keys)
    return jsonify({"success": True, "keys": new_keys})


@require_admin
def handle_list_keys():
    search = request.form.get("search", "").lower()
    filter_status = request.form.get("status", "")

    try:
        query = {}
        if filter_status:
            query["status"] = filter_status
        
        all_docs = list(keys_collection.find(query).sort("created", -1).limit(200))
        rows = []
        
        for doc in all_docs:
            if search:
                key = doc.get("key", "")
                note = doc.get("note", "")
                if search not in key.lower() and search not in str(note).lower():
                    continue
            
            doc.pop("_id", None)
            rows.append(doc)
        
        return jsonify({"success": True, "keys": rows})
    except Exception as e:
        print(f"Error listing keys: {e}")
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
        print(f"Error getting stats: {e}")
        return jsonify({
            "success": True,
            "total": 0,
            "active": 0,
            "used": 0,
            "expired": 0,
            "unused": 0,
            "banned": 0
        })


@require_admin
def handle_delete_key():
    key = request.form.get("key", "")
    
    try:
        delete_key_db(key)
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error deleting key: {e}")
        return jsonify({"success": False, "message": "Failed to delete key."})


@require_admin
def handle_reset_hwid():
    key = request.form.get("key", "")
    
    try:
        keys_collection.update_one(
            {"key": key},
            {
                "$set": {
                    "hwid": None,
                    "status": "unused"
                }
            }
        )
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error resetting HWID: {e}")
        return jsonify({"success": False, "message": "Failed to reset HWID."})


@require_admin
def handle_upload_library():
    if "library_file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded."})

    file = request.files["library_file"]
    lib_name = request.form.get("lib_name", "").strip()
    lib_version = request.form.get("lib_version", "").strip()
    lib_description = request.form.get("lib_description", "").strip()

    if not lib_name:
        return jsonify({"success": False, "message": "Library name is required."})

    if not file or file.filename == "":
        return jsonify({"success": False, "message": "No file selected."})

    if not file.filename.endswith(".so"):
        return jsonify({"success": False, "message": "Only .SO files are allowed."})

    if file.content_length and file.content_length > MAX_FILE_SIZE:
        return jsonify({"success": False, "message": "File exceeds 20 MB limit."})

    filename = secure_filename(file.filename)
    filepath = os.path.join(LIBRARIES_DIR, filename)

    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        if file_size > MAX_FILE_SIZE:
            os.remove(filepath)
            return jsonify({"success": False, "message": "File exceeds 20 MB limit."})

        lib_data = {
            "filename": filename,
            "size": file_size,
            "version": lib_version if lib_version else None,
            "description": lib_description if lib_description else None,
            "uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        libraries_collection.update_one(
            {"filename": filename},
            {"$set": lib_data},
            upsert=True
        )

        return jsonify({"success": True, "message": "Library uploaded successfully."})
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        print(f"Error uploading library: {e}")
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
        print(f"Error listing libraries: {e}")
        return jsonify({"success": True, "libraries": []})


@require_admin
def handle_delete_library():
    filename = secure_filename(request.form.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    try:
        if os.path.exists(filepath) and os.path.isfile(filepath):
            os.remove(filepath)

        delete_library_db(filename)
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error deleting library: {e}")
        return jsonify({"success": False, "message": f"Failed to delete library: {str(e)}"})


@require_admin
def handle_download_library():
    filename = secure_filename(request.args.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"success": False, "message": "File not found."}), 404

    try:
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Error downloading library: {e}")
        return jsonify({"success": False, "message": f"Download failed: {str(e)}"}), 500


def handle_login():
    user_key = request.form.get("user_key", "")
    if not user_key:
        return jsonify({"success": False, "message": "Key required."})

    try:
        key_doc = keys_collection.find_one({"key": user_key})
        
        if not key_doc:
            return jsonify({"success": False, "message": "Invalid key."})

        if key_doc.get("status") == "banned":
            return jsonify({"success": False, "message": "Key is banned."})

        if key_doc.get("expires"):
            if datetime.strptime(key_doc["expires"], "%Y-%m-%d %H:%M:%S").timestamp() < time.time():
                keys_collection.update_one(
                    {"key": user_key},
                    {"$set": {"status": "expired"}}
                )
                return jsonify({"success": False, "message": "Key has expired."})

        if key_doc.get("status") == "expired":
            return jsonify({"success": False, "message": "Key has expired."})

        return jsonify(
            {"success": True, "expiry": key_doc.get("expires") if key_doc.get("expires") else "Lifetime"}
        )
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({"success": False, "message": "Login error."})


def handle_connect():
    game = request.form.get("game", "")
    auth = request.form.get("auth", "")
    user_key = request.form.get("user_key", "")
    serial = request.form.get("serial", "")
    t = request.form.get("t", "0")
    sig = request.form.get("sig", "")

    try:
        t_int = int(t)
    except:
        return send_enc_err("Invalid timestamp", AES_KEY)

    app.logger.info(f"Connect request: game={game}, user_key={user_key}")

    if game != GAME_ID:
        return send_enc_err("Invalid game ID", AES_KEY)

    if abs(time.time() - t_int) > 60:
        return send_enc_err("Timestamp expired", AES_KEY)

    message = f"game={game}&auth={auth}&user_key={user_key}&serial={serial}&t={t}"
    expected_sig = hmac_sha256(message, AES_KEY)

    if not hmac.compare_digest(expected_sig, sig):
        app.logger.warning(f"Signature mismatch: expected={expected_sig}, got={sig}")
        return send_enc_err("Signature mismatch", AES_KEY)

    try:
        key_doc = keys_collection.find_one({"key": user_key})

        if not key_doc:
            return send_enc_err("Key not found", AES_KEY)

        if key_doc.get("status") == "banned":
            return send_enc_err("Key is banned", AES_KEY)

        if key_doc.get("expires"):
            expiry_time = datetime.strptime(key_doc["expires"], "%Y-%m-%d %H:%M:%S").timestamp()
            if expiry_time < time.time():
                keys_collection.update_one(
                    {"key": user_key},
                    {"$set": {"status": "expired"}}
                )
                return send_enc_err("Key has expired", AES_KEY)

        if key_doc.get("hwid") and key_doc["hwid"] != serial:
            return send_enc_err("HWID mismatch", AES_KEY)

        if not key_doc.get("hwid"):
            keys_collection.update_one(
                {"key": user_key},
                {
                    "$set": {
                        "hwid": serial,
                        "status": "active"
                    }
                }
            )

        keys_collection.update_one(
            {"key": user_key},
            {"$set": {"last_used": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}}
        )

        checked_str = f"{GAME_ID}-{user_key}-{serial}-{auth}-{t}-{SECRET_SALT}"
        checked = hashlib.md5(checked_str.encode("utf-8")).hexdigest()

        token = hashlib.md5(user_key.encode("utf-8")).hexdigest()

        response_data = {
            "status": SUCCESS_STATUS,
            "data": {
                "token": token,
                "rng": int(time.time()),
                "expiredDate": key_doc.get("expires") if key_doc.get("expires") else "Lifetime",
                "checked": checked,
            },
        }

        return send_enc_payload(response_data, AES_KEY)
    except Exception as e:
        print(f"Error during connect: {e}")
        return send_enc_err("Connection error", AES_KEY)


# ========== Static File Routes ==========

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')


@app.route('/admin')
def dashboard():
    return send_from_directory('.', 'admin.html')


@app.route('/<path:filename>')
def serve_files(filename):
    return send_from_directory('.', filename)


if __name__ == "__main__":
    print(f"Server starting with MongoDB integration..")
    print(f"Database: {db.name}")
    print(f"Collections: {db.list_collection_names()}")
    app.run(debug=False, host="0.0.0.0", port=5000)
