# app.py - CFL License System (Python/Flask version)

from flask import Flask, request, jsonify, send_from_directory
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

# ─── CONFIG ───────────────────────────────────────────────────────────────────
ADMIN_PASSWORD = 'changeme'  # Change this!
KEYS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'keys.json')
SESSION_FILE = os.path.join(os.path.dirname(__file__), 'data', 'sessions.json')
AES_KEY_B64 = 'ijIe7lzCGmmunuhiZ6I/f97NNBAVlLmhaEsfDZJe8eU='
GAME_ID = 'CFL'
SECRET_SALT = 'Nh3Dv2WJ9jxfsbEzqWjRlA4KgFY9VQ8H'
SUCCESS_STATUS = 945734
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Ensure data directory exists
os.makedirs(os.path.dirname(KEYS_FILE), exist_ok=True)

# ─── FILE HELPERS ─────────────────────────────────────────────────────────────

def load_keys():
    """Load keys from JSON file"""
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}

def save_keys(keys):
    """Save keys to JSON file"""
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)

def load_sessions():
    """Load admin sessions from JSON file"""
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}

def save_sessions(sessions):
    """Save admin sessions to JSON file"""
    with open(SESSION_FILE, 'w') as f:
        json.dump(sessions, f, indent=2)

def make_key():
    """Generate a license key in format: XXXXXX-XXXXXX-XXXXXX-XXXXXX"""
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    parts = []
    for g in range(4):
        part = ''.join(random.choice(chars) for _ in range(6))
        parts.append(part)
    return '-'.join(parts)

# ─── DECORATORS ───────────────────────────────────────────────────────────────

def require_admin(f):
    """Decorator to check admin authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get('token', '')
        if not token:
            return jsonify({'success': False, 'message': 'Unauthorized'})
        
        sessions = load_sessions()
        # Clean expired sessions
        current_time = time.time()
        sessions = {k: v for k, v in sessions.items() if v.get('exp', 0) > current_time}
        
        if token not in sessions:
            return jsonify({'success': False, 'message': 'Session expired. Please log in again.'})
        
        save_sessions(sessions)
        return f(*args, **kwargs)
    return decorated

# ─── ENCRYPTION HELPERS ───────────────────────────────────────────────────────

def send_enc_payload(json_str, key):
    """Send encrypted payload"""
    key_bytes = base64.b64decode(AES_KEY_B64)
    iv = os.urandom(12)
    
    # For AES-256-GCM, we need to use cryptography library or pycryptodome
    # This is a simplified version - in production use proper crypto library
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    aesgcm = AESGCM(key_bytes)
    ct = aesgcm.encrypt(iv, json_str.encode('utf-8'), None)
    
    payload = base64.b64encode(iv + ct).decode('utf-8')
    hmac_val = hmac.new(key_bytes, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    
    return jsonify({
        'enc': True,
        'payload': payload,
        'hmac': hmac_val
    })

def send_enc_err(reason, key):
    """Send encrypted error response"""
    return send_enc_payload(json.dumps({'status': 0, 'reason': reason}), key)

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/api.php', methods=['POST', 'GET', 'OPTIONS'])
def api_handler():
    """Main API endpoint"""
    if request.method == 'OPTIONS':
        return '', 200
    
    action = request.values.get('action', '').strip()
    
    if action == 'ping':
        return handle_ping()
    elif action == 'admin_login':
        return handle_admin_login()
    elif action == 'generate_keys':
        return handle_generate_keys()
    elif action == 'list_keys':
        return handle_list_keys()
    elif action == 'get_stats':
        return handle_get_stats()
    elif action == 'delete_key':
        return handle_delete_key()
    elif action == 'reset_hwid':
        return handle_reset_hwid()
    elif action == 'login':
        return handle_login()
    elif action == 'connect':
        return handle_connect()
    else:
        return jsonify({'success': False, 'message': f"Unknown action: '{action}'"})

def handle_ping():
    """Ping endpoint"""
    return jsonify({'success': True, 'status': 'online'})

def handle_admin_login():
    """Admin login"""
    password = request.form.get('password', '')
    if not password:
        return jsonify({'success': False, 'message': 'Password required.'})
    
    if not hmac.compare_digest(ADMIN_PASSWORD, password):
        return jsonify({'success': False, 'message': 'Invalid password.'})
    
    token = secrets.token_hex(32)
    sessions = load_sessions()
    
    # Clean expired sessions
    current_time = time.time()
    sessions = {k: v for k, v in sessions.items() if v.get('exp', 0) > current_time}
    
    sessions[token] = {'exp': current_time + 7200}  # 2 hours
    save_sessions(sessions)
    
    return jsonify({'success': True, 'token': token})

@require_admin
def handle_generate_keys():
    """Generate new license keys"""
    duration = int(request.form.get('duration', 0))
    qty = int(request.form.get('qty', 1))
    qty = max(1, min(100, qty))  # Limit between 1-100
    note = request.form.get('note', '')
    
    if duration > 0:
        expires = (datetime.now() + timedelta(days=duration)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        expires = None
    
    keys = load_keys()
    new_keys = []
    
    for _ in range(qty):
        while True:
            k = make_key()
            if k not in keys:
                break
        
        keys[k] = {
            'key': k,
            'status': 'unused',
            'hwid': None,
            'expires': expires,
            'note': note if note else None,
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_used': None
        }
        new_keys.append(k)
    
    save_keys(keys)
    return jsonify({'success': True, 'keys': new_keys})

@require_admin
def handle_list_keys():
    """List keys with filtering"""
    search = request.form.get('search', '').lower()
    status_filter = request.form.get('status', '')
    
    keys = load_keys()
    rows = []
    
    for k, row in keys.items():
        if status_filter and row['status'] != status_filter:
            continue
        
        if search:
            key_match = search in k.lower()
            note_match = search in (row.get('note', '') or '').lower() if row.get('note') else False
            if not (key_match or note_match):
                continue
        
        rows.append(row)
    
    # Sort by created date (newest first)
    rows.sort(key=lambda x: x.get('created', ''), reverse=True)
    
    return jsonify({'success': True, 'keys': rows[:200]})

@require_admin
def handle_get_stats():
    """Get key statistics"""
    keys = load_keys()
    total = len(keys)
    active = unused = expired = banned = 0
    
    current_time = time.time()
    
    for row in keys.values():
        # Check for expired keys
        if (row['status'] not in ['banned', 'expired'] and 
            row.get('expires') and 
            datetime.strptime(row['expires'], '%Y-%m-%d %H:%M:%S').timestamp() < current_time):
            row['status'] = 'expired'
        
        if row['status'] == 'active':
            active += 1
        elif row['status'] == 'unused':
            unused += 1
        elif row['status'] == 'expired':
            expired += 1
        elif row['status'] == 'banned':
            banned += 1
    
    return jsonify({
        'success': True,
        'total': total,
        'active': active,
        'used': active + expired,
        'expired': expired,
        'unused': unused,
        'banned': banned
    })

@require_admin
def handle_delete_key():
    """Delete a key"""
    key = request.form.get('key', '')
    keys = load_keys()
    
    if key in keys:
        del keys[key]
        save_keys(keys)
    
    return jsonify({'success': True})

@require_admin
def handle_reset_hwid():
    """Reset HWID for a key"""
    key = request.form.get('key', '')
    keys = load_keys()
    
    if key in keys:
        keys[key]['hwid'] = None
        keys[key]['status'] = 'unused'
        save_keys(keys)
    
    return jsonify({'success': True})

def handle_login():
    """User login endpoint"""
    user_key = request.form.get('user_key', '')
    if not user_key:
        return jsonify({'success': False, 'message': 'Key required.'})
    
    keys = load_keys()
    
    if user_key not in keys:
        return jsonify({'success': False, 'message': 'Invalid key.'})
    
    row = keys[user_key]
    
    if row['status'] == 'banned':
        return jsonify({'success': False, 'message': 'Key is banned.'})
    
    if row.get('expires'):
        if datetime.strptime(row['expires'], '%Y-%m-%d %H:%M:%S').timestamp() < time.time():
            keys[user_key]['status'] = 'expired'
            save_keys(keys)
            return jsonify({'success': False, 'message': 'Key has expired.'})
    
    if row['status'] == 'expired':
        return jsonify({'success': False, 'message': 'Key has expired.'})
    
    return jsonify({
        'success': True,
        'expiry': row['expires'] if row['expires'] else 'Lifetime'
    })

def handle_connect():
    """Connect endpoint for game client"""
    aes_key = base64.b64decode(AES_KEY_B64)
    
    game = request.form.get('game', '')
    auth = request.form.get('auth', '')
    user_key = request.form.get('user_key', '')
    serial = request.form.get('serial', '')
    t = int(request.form.get('t', 0))
    sig = request.form.get('sig', '')
    
    # Verify game ID and timestamp
    if game != GAME_ID or abs(time.time() - t) > 60:
        return send_enc_err('Rejected', aes_key)
    
    # Verify signature
    message = f"game={game}&auth={auth}&user_key={user_key}&serial={serial}&t={t}"
    expected_sig = hmac.new(aes_key, message.encode('utf-8'), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_sig, sig):
        return send_enc_err('Signature mismatch', aes_key)
    
    keys = load_keys()
    
    if user_key not in keys:
        return send_enc_err('Key not found', aes_key)
    
    row = keys[user_key]
    
    if row['status'] == 'banned':
        return send_enc_err('Banned', aes_key)
    
    # Check expiration
    if row.get('expires'):
        if datetime.strptime(row['expires'], '%Y-%m-%d %H:%M:%S').timestamp() < time.time():
            keys[user_key]['status'] = 'expired'
            save_keys(keys)
            return send_enc_err('Expired', aes_key)
    
    # Check HWID
    if row.get('hwid') and row['hwid'] != serial:
        return send_enc_err('HWID mismatch', aes_key)
    
    # Set HWID if not set
    if not row.get('hwid'):
        keys[user_key]['hwid'] = serial
        keys[user_key]['status'] = 'active'
    
    keys[user_key]['last_used'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    save_keys(keys)
    
    # Generate response
    checked = hashlib.md5(
        f"{GAME_ID}-{user_key}-{serial}-{auth}-{t}-{SECRET_SALT}".encode('utf-8')
    ).hexdigest()
    
    response_data = {
        'status': SUCCESS_STATUS,
        'data': {
            'token': hashlib.md5(user_key.encode('utf-8')).hexdigest(),
            'rng': int(time.time()),
            'expiredDate': row['expires'] if row['expires'] else 'Lifetime',
            'checked': checked
        }
    }
    
    return send_enc_payload(json.dumps(response_data), aes_key)

# ─── SERVE HTML FILES ─────────────────────────────────────────────────────────

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("CFL License System - Python Backend")
    print(f"Data directory: {os.path.dirname(KEYS_FILE)}")
    print("Starting server on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
