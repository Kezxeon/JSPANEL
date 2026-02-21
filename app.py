# app.py - Updated with Library Management System

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
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


ADMIN_PASSWORD = "changeme"
KEYS_FILE = os.path.join(os.path.dirname(__file__), "data", "keys.json")
LIBRARIES_FILE = os.path.join(os.path.dirname(__file__), "data", "libraries.json")
SESSION_FILE = os.path.join(os.path.dirname(__file__), "data", "sessions.json")
LIBRARIES_DIR = os.path.join(os.path.dirname(__file__), "AzxLibraries")
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
AES_KEY_B64 = "ijIe7lzCGmmunuhiZ6I/f97NNBAVlLmhaEsfDZJe8eU="
GAME_ID = "AzxiePanel"
SECRET_SALT = "Nh3Dv2WJ9jxfsbEzqWjRlA4KgFY9VQ8H"
SUCCESS_STATUS = 945734

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

AES_KEY = base64.b64decode(AES_KEY_B64)

os.makedirs(os.path.dirname(KEYS_FILE), exist_ok=True)
os.makedirs(LIBRARIES_DIR, exist_ok=True)


def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


def load_libraries():
    if not os.path.exists(LIBRARIES_FILE):
        return {}
    try:
        with open(LIBRARIES_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}


def save_libraries(libs):
    with open(LIBRARIES_FILE, "w") as f:
        json.dump(libs, f, indent=2)


def load_sessions():
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}


def save_sessions(sessions):
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)


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

        sessions = load_sessions()
        current_time = time.time()
        sessions = {k: v for k, v in sessions.items() if v.get("exp", 0) > current_time}

        if token not in sessions:
            return jsonify(
                {"success": False, "message": "Session expired. Please log in again."}
            )

        save_sessions(sessions)
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
    sessions = load_sessions()

    current_time = time.time()
    sessions = {k: v for k, v in sessions.items() if v.get("exp", 0) > current_time}

    sessions[token] = {"exp": current_time + 7200}
    save_sessions(sessions)

    return jsonify({"success": True, "token": token})


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
    status_filter = request.form.get("status", "")

    keys = load_keys()
    rows = []

    for k, row in keys.items():
        if status_filter and row["status"] != status_filter:
            continue

        if search:
            key_match = search in k.lower()
            note_match = (
                search in (row.get("note", "") or "").lower()
                if row.get("note")
                else False
            )
            if not (key_match or note_match):
                continue

        rows.append(row)

    rows.sort(key=lambda x: x.get("created", ""), reverse=True)

    return jsonify({"success": True, "keys": rows[:200]})


@require_admin
def handle_get_stats():

    keys = load_keys()
    total = len(keys)
    active = unused = expired = banned = 0

    current_time = time.time()

    for row in keys.values():
        if (
            row["status"] not in ["banned", "expired"]
            and row.get("expires")
            and datetime.strptime(row["expires"], "%Y-%m-%d %H:%M:%S").timestamp()
            < current_time
        ):
            row["status"] = "expired"

        if row["status"] == "active":
            active += 1
        elif row["status"] == "unused":
            unused += 1
        elif row["status"] == "expired":
            expired += 1
        elif row["status"] == "banned":
            banned += 1

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


@require_admin
def handle_delete_key():

    key = request.form.get("key", "")
    keys = load_keys()

    if key in keys:
        del keys[key]
        save_keys(keys)

    return jsonify({"success": True})


@require_admin
def handle_reset_hwid():

    key = request.form.get("key", "")
    keys = load_keys()

    if key in keys:
        keys[key]["hwid"] = None
        keys[key]["status"] = "unused"
        save_keys(keys)

    return jsonify({"success": True})


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

        libs = load_libraries()
        libs[filename] = {
            "filename": filename,
            "size": file_size,
            "version": lib_version if lib_version else None,
            "description": lib_description if lib_description else None,
            "uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        save_libraries(libs)

        return jsonify({"success": True, "message": "Library uploaded successfully."})
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({"success": False, "message": f"Upload failed: {str(e)}"})


@require_admin
def handle_list_libraries():
    search = request.form.get("search", "").lower()
    libs = load_libraries()
    rows = []

    for lib in libs.values():
        if search and search not in lib["filename"].lower():
            continue
        rows.append(lib)

    rows.sort(key=lambda x: x.get("uploaded", ""), reverse=True)
    return jsonify({"success": True, "libraries": rows[:200]})


@require_admin
def handle_delete_library():
    filename = secure_filename(request.form.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    if os.path.exists(filepath) and os.path.isfile(filepath):
        try:
            os.remove(filepath)
        except Exception as e:
            return jsonify({"success": False, "message": f"Failed to delete file: {str(e)}"})

    libs = load_libraries()
    if filename in libs:
        del libs[filename]
        save_libraries(libs)

    return jsonify({"success": True})


@require_admin
def handle_download_library():
    filename = secure_filename(request.args.get("filename", ""))
    filepath = os.path.join(LIBRARIES_DIR, filename)

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"success": False, "message": "File not found."}), 404

    try:
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"success": False, "message": f"Download failed: {str(e)}"}), 500


def handle_login():

    user_key = request.form.get("user_key", "")
    if not user_key:
        return jsonify({"success": False, "message": "Key required."})

    keys = load_keys()

    if user_key not in keys:
        return jsonify({"success": False, "message": "Invalid key."})

    row = keys[user_key]

    if row["status"] == "banned":
        return jsonify({"success": False, "message": "Key is banned."})

    if row.get("expires"):
        if (
            datetime.strptime(row["expires"], "%Y-%m-%d %H:%M:%S").timestamp()
            < time.time()
        ):
            keys[user_key]["status"] = "expired"
            save_keys(keys)
            return jsonify({"success": False, "message": "Key has expired."})

    if row["status"] == "expired":
        return jsonify({"success": False, "message": "Key has expired."})

    return jsonify(
        {"success": True, "expiry": row["expires"] if row["expires"] else "Lifetime"}
    )


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

    keys = load_keys()

    if user_key not in keys:
        return send_enc_err("Key not found", AES_KEY)

    row = keys[user_key]

    if row["status"] == "banned":
        return send_enc_err("Key is banned", AES_KEY)

    if row.get("expires"):
        expiry_time = datetime.strptime(row["expires"], "%Y-%m-%d %H:%M:%S").timestamp()
        if expiry_time < time.time():
            keys[user_key]["status"] = "expired"
            save_keys(keys)
            return send_enc_err("Key has expired", AES_KEY)

    if row.get("hwid") and row["hwid"] != serial:
        return send_enc_err("HWID mismatch", AES_KEY)

    if not row.get("hwid"):
        keys[user_key]["hwid"] = serial
        keys[user_key]["status"] = "active"

    keys[user_key]["last_used"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_keys(keys)

    checked_str = f"{GAME_ID}-{user_key}-{serial}-{auth}-{t}-{SECRET_SALT}"
    checked = hashlib.md5(checked_str.encode("utf-8")).hexdigest()

    token = hashlib.md5(user_key.encode("utf-8")).hexdigest()

    response_data = {
        "status": SUCCESS_STATUS,
        "data": {
            "token": token,
            "rng": int(time.time()),
            "expiredDate": row["expires"] if row["expires"] else "Lifetime",
            "checked": checked,
        },
    }

    return send_enc_payload(response_data, AES_KEY)


@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory('.', 'admin.html')

@app.route('/api')
def api_redirect():
    return send_from_directory('.', 'api.php')

# Keep static files accessible
@app.route('/<path:filename>')
def serve_files(filename):
    return send_from_directory('.', filename)

if __name__ == "__main__":
    print(f"Server starting..")
    app.run(debug=False, host="0.0.0.0", port=5000)
