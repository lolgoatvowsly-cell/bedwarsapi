"""
Simple API Server - Personal Keys Only
Each user gets their own unique key tied to their Discord ID
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# =============================================
# CONFIGURATION
# =============================================
class Config:
    DATABASE_PATH = os.getenv("DATABASE_PATH", "auth.db")
    PORT = int(os.getenv("PORT", 5000))
    HOST = os.getenv("HOST", "0.0.0.0")
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

def print_config():
    print("=" * 50)
    print("API Configuration:")
    print("=" * 50)
    print(f"Database: {Config.DATABASE_PATH}")
    print(f"Port: {Config.PORT}")
    print(f"Webhook: {'✅ Configured' if Config.DISCORD_WEBHOOK_URL else '❌ Not set'}")
    print("=" * 50)

# =============================================
# DATABASE
# =============================================
def init_database():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            personal_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            is_active INTEGER DEFAULT 1,
            expiry_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_hwid_reset TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT,
            hwid TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            blacklisted_by TEXT NOT NULL,
            blacklisted_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT,
            hwid TEXT,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def get_db():
    return sqlite3.connect(Config.DATABASE_PATH)

def log_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"📡 {request.method} {request.path} from {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

def log_activity(discord_id=None, hwid=None, action="", details=""):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO activity_logs (discord_id, hwid, action, details) VALUES (?, ?, ?, ?)",
            (discord_id, hwid, action, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ Failed to log activity: {e}")

# =============================================
# ROUTES
# =============================================
@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'Bedwars ESP API',
        'status': 'online',
        'version': '3.0.1 - Fixed Edition',
        'endpoints': {
            'health': 'GET /health',
            'verify_key': 'POST /verify-key',
            'loader': 'GET /v3/files/loaders/esp.lua',
            'esp_script': 'GET /v3/files/scripts/esp-main.lua',
            'stats': 'GET /admin/stats'
        }
    })

@app.route('/health', methods=['GET'])
@log_request
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/verify-key', methods=['POST'])
@log_request
def verify_key():
    """Verify personal key and check blacklist"""
    try:
        data = request.get_json()
        
        if not data or 'script_key' not in data:
            return jsonify({'error': 'script_key required'}), 400
        
        personal_key = data['script_key']
        hwid = data.get('hwid')
        
        print(f"🔐 Verifying key: {personal_key[:16]}... with HWID: {hwid[:16] if hwid else 'None'}...")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Find user by their personal key
        cursor.execute(
            "SELECT discord_id, username, is_active, expiry_date, hwid FROM users WHERE personal_key = ?",
            (personal_key,)
        )
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            print(f"❌ Invalid key: {personal_key[:16]}...")
            log_activity(hwid=hwid, action="INVALID_KEY", details=f"Key: {personal_key[:16]}...")
            return jsonify({'valid': False, 'error': 'Invalid personal key'}), 403
        
        discord_id, username, is_active, expiry_date, registered_hwid = user
        
        print(f"✅ Found user: {username} (Discord ID: {discord_id})")
        
        # Check if active
        if not is_active:
            conn.close()
            print(f"❌ User {username} is inactive")
            log_activity(discord_id=discord_id, hwid=hwid, action="INACTIVE_USER", details="User is deactivated")
            return jsonify({'valid': False, 'error': 'Access revoked'}), 403
        
        # Check if expired
        if expiry_date:
            expiry = datetime.fromisoformat(expiry_date)
            if expiry < datetime.now():
                conn.close()
                print(f"❌ User {username} subscription expired on {expiry_date}")
                log_activity(discord_id=discord_id, hwid=hwid, action="EXPIRED_USER", details="Subscription expired")
                return jsonify({'valid': False, 'error': 'Subscription expired'}), 403
        
        # Check if HWID is blacklisted
        if hwid:
            cursor.execute("SELECT reason FROM blacklist WHERE hwid = ?", (hwid,))
            blacklist_result = cursor.fetchone()
            
            if blacklist_result:
                conn.close()
                print(f"🚫 HWID {hwid[:16]}... is blacklisted")
                log_activity(discord_id=discord_id, hwid=hwid, action="BLACKLIST_ATTEMPT", details="HWID is blacklisted")
                return jsonify({
                    'valid': False,
                    'blacklisted': True,
                    'reason': blacklist_result[0]
                }), 403
            
            # Register or update HWID
            if not registered_hwid:
                print(f"📝 Registering HWID for {username}: {hwid[:16]}...")
                cursor.execute(
                    "UPDATE users SET hwid = ? WHERE discord_id = ?",
                    (hwid, discord_id)
                )
                conn.commit()
                log_activity(discord_id=discord_id, hwid=hwid, action="HWID_REGISTERED", details="First time execution")
            elif registered_hwid != hwid:
                # HWID changed - potential HWID reset or new device
                print(f"⚠️ HWID changed for {username}: {registered_hwid[:16]}... -> {hwid[:16]}...")
                log_activity(discord_id=discord_id, hwid=hwid, action="HWID_CHANGED", details=f"Old: {registered_hwid[:16]}...")
                cursor.execute(
                    "UPDATE users SET hwid = ? WHERE discord_id = ?",
                    (hwid, discord_id)
                )
                conn.commit()
        
        conn.close()
        
        print(f"✅ Key verified successfully for {username}")
        log_activity(discord_id=discord_id, hwid=hwid, action="KEY_VERIFIED", details=f"User: {username}")
        
        return jsonify({
            'valid': True,
            'script_name': 'Bedwars ESP',
            'version': '1.0.0',
            'username': username
        })
        
    except Exception as e:
        print(f"❌ Error verifying key: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/v3/files/loaders/esp.lua', methods=['GET'])
@log_request
def get_esp_loader():
    """Return the ESP loader script"""
    try:
        # Get the base URL (ensure HTTPS for Render)
        api_url = request.host_url.rstrip('/')
        if 'render.com' in api_url:
            api_url = api_url.replace('http://', 'https://')
        
        esp_template = '''-- Bedwars ESP Loader - Updated Edition
-- Each user has their own personal key

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

-- Check if scriptkey variable exists
if not scriptkey then
    LocalPlayer:Kick("❌ Missing script key!\\n\\nUsage:\\nscriptkey = \\"YOUR_KEY\\";\\nloadstring(game:HttpGet(...))()")
    return
end

local PERSONAL_KEY = scriptkey
local API_URL = "''' + api_url + '''"
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()

print("🔐 Verifying your personal key...")
print("📍 HWID: " .. HWID:sub(1, 16) .. "...")

-- Verify key with API
local function verifyKey()
    local success, result = pcall(function()
        -- Use game:HttpPost for Roblox
        local response = game:HttpPost(
            API_URL .. "/verify-key",
            HttpService:JSONEncode({
                script_key = PERSONAL_KEY,
                hwid = HWID
            }),
            Enum.HttpContentType.ApplicationJson
        )
        return HttpService:JSONDecode(response)
    end)
    
    if not success then
        local errorMsg = tostring(result)
        warn("❌ API Error: " .. errorMsg)
        
        -- Better error messages
        if errorMsg:find("403") or errorMsg:find("Forbidden") then
            LocalPlayer:Kick("❌ INVALID KEY!\\n\\nYour key was rejected by the API.\\n\\nGet your key from Discord using /getscript")
        elseif errorMsg:find("Http requests are not enabled") then
            LocalPlayer:Kick("❌ HTTP REQUESTS NOT ENABLED!\\n\\nEnable HttpService in game settings.")
        else
            LocalPlayer:Kick("❌ Failed to connect to API!\\n\\n" .. errorMsg)
        end
        return false
    end
    
    if not result then
        LocalPlayer:Kick("❌ No response from API!")
        return false
    end
    
    if result.blacklisted then
        LocalPlayer:Kick("🚫 HWID BLACKLISTED\\n\\nReason: " .. (result.reason or "Banned"))
        return false
    end
    
    if not result.valid then
        LocalPlayer:Kick("❌ " .. (result.error or "Invalid key") .. "\\n\\nGet your key from Discord using /getscript")
        return false
    end
    
    return true, result
end

-- Verify and load
local verified, data = verifyKey()

if not verified then
    return
end

print("✅ Authenticated as: " .. data.username)
print("✅ Loading " .. data.script_name .. " v" .. data.version)

-- Load the actual ESP script
local success, err = pcall(function()
    loadstring(game:HttpGet(API_URL .. "/v3/files/scripts/esp-main.lua"))()
end)

if not success then
    warn("❌ ESP Load Error: " .. tostring(err))
    LocalPlayer:Kick("❌ Failed to load ESP!\\n\\n" .. tostring(err))
end
'''
        
        return esp_template, 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        print(f"❌ Error serving ESP loader: {e}")
        return f"-- Error: {str(e)}", 500, {'Content-Type': 'text/plain'}

@app.route('/v3/files/scripts/esp-main.lua', methods=['GET'])
@log_request
def get_esp_main():
    """Return the main ESP script"""
    try:
        esp_main_path = os.path.join(os.path.dirname(__file__), 'esp-main.lua')
        
        if os.path.exists(esp_main_path):
            with open(esp_main_path, 'r') as f:
                return f.read(), 200, {'Content-Type': 'text/plain'}
        else:
            return '''-- Bedwars ESP Main Script
print("✅ ESP Loaded!")
print("📍 HWID: " .. game:GetService("RbxAnalyticsService"):GetClientId():sub(1, 16) .. "...")
print("🎮 Press INSERT to toggle ESP")

-- Your full ESP code goes here
''', 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        print(f"❌ Error serving ESP main: {e}")
        return f"-- Error: {str(e)}", 500, {'Content-Type': 'text/plain'}

@app.route('/tamper-alert', methods=['POST'])
@log_request
def tamper_alert():
    """Receive tamper alerts"""
    try:
        data = request.get_json()
        
        if Config.DISCORD_WEBHOOK_URL:
            try:
                import requests
                requests.post(
                    Config.DISCORD_WEBHOOK_URL,
                    json=data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                print("✅ Alert forwarded to Discord")
            except Exception as e:
                print(f"❌ Error forwarding alert: {e}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ Error handling alert: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================
# ADMIN ENDPOINTS
# =============================================
@app.route('/admin/whitelist-user', methods=['POST'])
@log_request
def admin_whitelist_user():
    """Whitelist a user (called from Discord bot)"""
    try:
        data = request.get_json()
        
        print(f"📥 Received whitelist request: {data}")
        
        if not data or 'discord_id' not in data or 'personal_key' not in data:
            print("❌ Missing required fields")
            return jsonify({'error': 'discord_id and personal_key required'}), 400
        
        discord_id = data['discord_id']
        personal_key = data['personal_key']
        username = data.get('username', 'Unknown')
        expiry_date = data.get('expiry_date')  # NEW: Accept expiry date
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE discord_id = ?", (discord_id,))
            existing = cursor.fetchone()
            
            if existing:
                print(f"⚠️ User {username} already exists, updating...")
                # Update existing user
                cursor.execute(
                    "UPDATE users SET personal_key = ?, username = ?, expiry_date = ?, is_active = 1 WHERE discord_id = ?",
                    (personal_key, username, expiry_date, discord_id)
                )
            else:
                print(f"➕ Adding new user {username}...")
                # Insert new user
                cursor.execute(
                    "INSERT INTO users (discord_id, username, personal_key, expiry_date, is_active) VALUES (?, ?, ?, ?, 1)",
                    (discord_id, username, personal_key, expiry_date)
                )
            
            conn.commit()
            
            print(f"✅ Successfully whitelisted {username} with key {personal_key}")
            log_activity(discord_id=discord_id, action="USER_WHITELISTED", details=f"User: {username}")
            
            return jsonify({'success': True, 'message': f'User {username} whitelisted successfully'})
            
        except sqlite3.IntegrityError as e:
            print(f"❌ Database integrity error: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 409
        finally:
            conn.close()
        
    except Exception as e:
        print(f"❌ Error whitelisting user: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/remove-whitelist', methods=['POST'])
@log_request
def admin_remove_whitelist():
    """Remove user from whitelist"""
    try:
        data = request.get_json()
        
        if not data or 'discord_id' not in data:
            return jsonify({'error': 'discord_id required'}), 400
        
        discord_id = data['discord_id']
        
        print(f"🗑️ Removing whitelist for Discord ID: {discord_id}")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("UPDATE users SET is_active = 0 WHERE discord_id = ?", (discord_id,))
        conn.commit()
        conn.close()
        
        print(f"✅ Successfully removed whitelist for {discord_id}")
        log_activity(discord_id=discord_id, action="USER_REMOVED", details="Removed from whitelist")
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ Error removing user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/blacklist', methods=['POST'])
@log_request
def admin_blacklist():
    """Add HWID to blacklist"""
    try:
        data = request.get_json()
        
        if not data or 'hwid' not in data or 'reason' not in data:
            return jsonify({'error': 'hwid and reason required'}), 400
        
        hwid = data['hwid']
        reason = data['reason']
        blacklisted_by = data.get('blacklisted_by', 'system')
        discord_id = data.get('discord_id')
        
        print(f"🚫 Blacklisting HWID: {hwid[:16]}... - Reason: {reason}")
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO blacklist (discord_id, hwid, reason, blacklisted_by) VALUES (?, ?, ?, ?)",
                (discord_id, hwid, reason, blacklisted_by)
            )
            
            cursor.execute("UPDATE users SET is_active = 0 WHERE hwid = ?", (hwid,))
            
            conn.commit()
            
            log_activity(discord_id=discord_id, hwid=hwid, action="HWID_BLACKLISTED", details=reason)
            
            print(f"✅ Successfully blacklisted HWID: {hwid[:16]}...")
            
            return jsonify({'success': True})
            
        except sqlite3.IntegrityError:
            print(f"⚠️ HWID {hwid[:16]}... already blacklisted")
            return jsonify({'error': 'HWID already blacklisted'}), 409
        finally:
            conn.close()
        
    except Exception as e:
        print(f"❌ Error blacklisting: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats', methods=['GET'])
@log_request
def admin_stats():
    """Get system statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM blacklist")
        blacklisted = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE hwid IS NOT NULL")
        with_hwid = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'blacklisted': blacklisted,
            'users_with_hwid': with_hwid
        })
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/hwid-list', methods=['GET'])
@log_request
def admin_hwid_list():
    """Get list of all registered HWIDs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT discord_id, username, hwid, created_at
            FROM users
            WHERE hwid IS NOT NULL
            ORDER BY created_at DESC
        """)
        
        hwids = []
        for row in cursor.fetchall():
            hwids.append({
                'discord_id': row[0],
                'username': row[1],
                'hwid': row[2],
                'registered': row[3]
            })
        
        conn.close()
        
        return jsonify({'hwids': hwids, 'total': len(hwids)})
        
    except Exception as e:
        print(f"❌ Error getting HWID list: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# =============================================
# STARTUP
# =============================================
if __name__ == '__main__':
    print("=" * 50)
    print("Simple Bedwars ESP API v3.0.1")
    print("=" * 50)
    
    print_config()
    init_database()
    
    print(f"✅ Server starting on http://{Config.HOST}:{Config.PORT}")
    print("=" * 50)
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )
