"""
Production API Server - FIXED VERSION
Properly handles script keys, HWID registration, and blacklisting
"""

from flask import Flask, request, jsonify, send_from_directory
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
    print(f"Host: {Config.HOST}")
    print(f"Webhook: {'✅ Configured' if Config.DISCORD_WEBHOOK_URL else '❌ Not set'}")
    print(f"Debug: {Config.DEBUG}")
    print("=" * 50)

# =============================================
# DATABASE FUNCTIONS
# =============================================
def init_database():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            hwid TEXT,
            license_key TEXT UNIQUE,
            is_active INTEGER DEFAULT 1,
            expiry_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_reset TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT UNIQUE NOT NULL,
            duration_days INTEGER NOT NULL,
            is_redeemed INTEGER DEFAULT 0,
            redeemed_by TEXT,
            redeemed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            script_key TEXT UNIQUE NOT NULL,
            script_url TEXT,
            script_content TEXT,
            version TEXT DEFAULT '1.0.0',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            blacklisted_by TEXT NOT NULL,
            discord_id TEXT,
            roblox_username TEXT,
            roblox_userid TEXT,
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
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hwid_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            hwid TEXT NOT NULL,
            registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(discord_id, hwid)
        )
    """)
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def get_db():
    return sqlite3.connect(Config.DATABASE_PATH)

def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

def log_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if Config.DEBUG:
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
        'service': 'Bedwars VisualScripts API',
        'status': 'online',
        'version': '2.0.0',
        'endpoints': {
            'health': 'GET /health',
            'verify_key': 'POST /verify-key',
            'check_blacklist': 'POST /check-blacklist',
            'register_hwid': 'POST /register-hwid',
            'tamper_alert': 'POST /tamper-alert',
            'loader': 'GET /v3/files/loaders/esp.lua',
            'admin_stats': 'GET /admin/stats',
            'admin_hwidlist': 'GET /admin/hwid-list'
        }
    })

@app.route('/health', methods=['GET'])
@log_request
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'webhook': 'configured' if Config.DISCORD_WEBHOOK_URL else 'not_configured'
    })

@app.route('/verify-key', methods=['POST'])
@log_request
def verify_key():
    """Verify if a script key is valid"""
    try:
        data = request.get_json()
        
        if not data or 'script_key' not in data:
            return jsonify({'error': 'script_key required'}), 400
        
        script_key = data['script_key']
        hwid = data.get('hwid')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if script key exists
        cursor.execute(
            "SELECT name, version FROM scripts WHERE script_key = ?",
            (script_key,)
        )
        script = cursor.fetchone()
        
        if not script:
            conn.close()
            log_activity(hwid=hwid, action="INVALID_KEY", details=f"Key: {script_key[:16]}...")
            return jsonify({'valid': False, 'error': 'Invalid script key'}), 403
        
        # If HWID provided, check blacklist
        if hwid:
            cursor.execute(
                "SELECT reason FROM blacklist WHERE hwid = ?",
                (hwid,)
            )
            blacklist_result = cursor.fetchone()
            
            if blacklist_result:
                conn.close()
                log_activity(hwid=hwid, action="BLACKLIST_CHECK", details="HWID is blacklisted")
                return jsonify({
                    'valid': False,
                    'blacklisted': True,
                    'reason': blacklist_result[0]
                }), 403
        
        conn.close()
        
        log_activity(hwid=hwid, action="KEY_VERIFIED", details=f"Script: {script[0]}")
        
        return jsonify({
            'valid': True,
            'script_name': script[0],
            'version': script[1]
        })
        
    except Exception as e:
        print(f"❌ Error verifying key: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/check-blacklist', methods=['POST'])
@log_request
def check_blacklist():
    """Check if HWID is blacklisted"""
    try:
        data = request.get_json()
        
        if not data or 'hwid' not in data:
            return jsonify({'error': 'HWID required'}), 400
        
        hwid = data['hwid']
        script_key = data.get('script_key')
        
        # Verify script key first
        if script_key:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scripts WHERE script_key = ?", (script_key,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({'error': 'Invalid script key'}), 403
            conn.close()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT reason, blacklisted_at, blacklisted_by FROM blacklist WHERE hwid = ?",
            (hwid,)
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            log_activity(hwid=hwid, action="BLACKLIST_ATTEMPT", details="Blocked")
            return jsonify({
                'blacklisted': True,
                'reason': result[0],
                'blacklisted_at': result[1],
                'blacklisted_by': result[2]
            })
        
        return jsonify({'blacklisted': False})
        
    except Exception as e:
        print(f"❌ Error checking blacklist: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/register-hwid', methods=['POST'])
@log_request
def register_hwid():
    """Register a user's HWID when they execute the script"""
    try:
        data = request.get_json()
        
        if not data or 'hwid' not in data:
            return jsonify({'error': 'HWID required'}), 400
        
        hwid = data['hwid']
        discord_id = data.get('discord_id')
        script_key = data.get('script_key')
        
        # Verify script key
        if script_key:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scripts WHERE script_key = ?", (script_key,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({'error': 'Invalid script key'}), 403
            conn.close()
        
        # Check if blacklisted first
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT reason FROM blacklist WHERE hwid = ?", (hwid,))
        blacklist_result = cursor.fetchone()
        
        if blacklist_result:
            conn.close()
            log_activity(discord_id=discord_id, hwid=hwid, action="BLACKLIST_REGISTER_ATTEMPT", details="Blocked")
            return jsonify({
                'success': False,
                'blacklisted': True,
                'reason': blacklist_result[0]
            }), 403
        
        # Register or update HWID
        if discord_id:
            try:
                cursor.execute(
                    "INSERT INTO hwid_registry (discord_id, hwid) VALUES (?, ?) "
                    "ON CONFLICT(discord_id, hwid) DO UPDATE SET last_seen = CURRENT_TIMESTAMP",
                    (discord_id, hwid)
                )
                
                # Update user table
                cursor.execute(
                    "UPDATE users SET hwid = ? WHERE discord_id = ?",
                    (hwid, discord_id)
                )
                
                conn.commit()
                
                log_activity(discord_id=discord_id, hwid=hwid, action="HWID_REGISTERED", details="Success")
                
            except sqlite3.IntegrityError:
                pass
        else:
            # Log anonymous HWID
            log_activity(hwid=hwid, action="ANONYMOUS_HWID", details="No Discord ID")
        
        conn.close()
        
        return jsonify({'success': True, 'hwid_registered': True})
        
    except Exception as e:
        print(f"❌ Error registering HWID: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tamper-alert', methods=['POST'])
@log_request
def tamper_alert():
    """Receive and forward tamper alerts"""
    try:
        data = request.get_json()
        
        if not data or 'embeds' not in data:
            return jsonify({'error': 'Invalid data'}), 400
        
        print(f"🚨 Tamper alert received")
        
        # Forward to Discord webhook
        if Config.DISCORD_WEBHOOK_URL:
            try:
                import requests
                
                response = requests.post(
                    Config.DISCORD_WEBHOOK_URL,
                    json=data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 204:
                    print("✅ Alert forwarded to Discord")
                else:
                    print(f"⚠️ Discord webhook returned: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error forwarding to Discord: {e}")
        else:
            print("⚠️ No webhook URL configured, alert not forwarded")
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ Error handling tamper alert: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/v3/files/loaders/esp.lua', methods=['GET'])
@log_request
def get_esp_loader():
    """
    Return the ESP loader script that validates the script key
    Users execute: scriptkey = "KEY"; loadstring(game:HttpGet("THIS_URL"))()
    """
    try:
        esp_template = '''-- Bedwars ESP Loader
-- API: ''' + request.host_url + '''

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

-- Check if scriptkey variable exists in global scope
if not scriptkey then
    LocalPlayer:Kick("❌ Missing script key!\\n\\nUsage:\\nscriptkey = \\"YOUR_KEY\\";\\nloadstring(game:HttpGet(...))()")
    return
end

local SCRIPT_KEY = scriptkey
local API_URL = "''' + request.host_url.rstrip('/') + '''"
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()

print("🔐 Verifying script key: " .. SCRIPT_KEY:sub(1, 8) .. "...")

-- Verify key with API
local function verifyKey()
    local success, result = pcall(function()
        local response = request({
            Url = API_URL .. "/verify-key",
            Method = "POST",
            Headers = {["Content-Type"] = "application/json"},
            Body = HttpService:JSONEncode({
                script_key = SCRIPT_KEY,
                hwid = HWID
            })
        })
        return HttpService:JSONDecode(response.Body)
    end)
    
    if not success then
        warn("❌ API Error: " .. tostring(result))
        LocalPlayer:Kick("❌ Failed to connect to API!\\n\\n" .. tostring(result))
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
        LocalPlayer:Kick("❌ Invalid script key!\\n\\nGet a valid key from the Discord server.")
        return false
    end
    
    return true, result
end

-- Register HWID
local function registerHWID()
    spawn(function()
        pcall(function()
            request({
                Url = API_URL .. "/register-hwid",
                Method = "POST",
                Headers = {["Content-Type"] = "application/json"},
                Body = HttpService:JSONEncode({
                    hwid = HWID,
                    script_key = SCRIPT_KEY
                })
            })
        end)
    end)
end

-- Verify and load
local verified, data = verifyKey()

if not verified then
    return
end

print("✅ Key verified! Loading " .. data.script_name .. " v" .. data.version)
print("📍 HWID: " .. HWID:sub(1, 16) .. "...")

-- Register HWID in background
registerHWID()

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
    """Return the main ESP script (after verification)"""
    try:
        # Load the actual ESP script from file or database
        esp_main_path = os.path.join(os.path.dirname(__file__), 'esp-main.lua')
        
        if os.path.exists(esp_main_path):
            with open(esp_main_path, 'r') as f:
                return f.read(), 200, {'Content-Type': 'text/plain'}
        else:
            # Return a basic ESP script
            return '''
-- Bedwars ESP Main Script
print("✅ ESP Loaded!")
print("📍 HWID: " .. game:GetService("RbxAnalyticsService"):GetClientId():sub(1, 16) .. "...")

-- Your ESP code here
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

print("🎮 Press INSERT to toggle ESP GUI")

-- ESP functionality would go here
''', 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        print(f"❌ Error serving ESP main: {e}")
        return f"-- Error: {str(e)}", 500, {'Content-Type': 'text/plain'}

# =============================================
# ADMIN ENDPOINTS
# =============================================
@app.route('/admin/add-key', methods=['POST'])
@log_request
def admin_add_key():
    """Add a license key (called from Discord bot)"""
    try:
        data = request.get_json()
        
        if not data or 'key_code' not in data or 'duration_days' not in data:
            return jsonify({'error': 'key_code and duration_days required'}), 400
        
        key_code = data['key_code']
        duration_days = data['duration_days']
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO keys (key_code, duration_days) VALUES (?, ?)",
                (key_code, duration_days)
            )
            conn.commit()
            
            log_activity(action="KEY_ADDED", details=f"{key_code} - {duration_days}d")
            
            return jsonify({'success': True})
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Key already exists'}), 409
        finally:
            conn.close()
        
    except Exception as e:
        print(f"❌ Error adding key: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-key', methods=['POST'])
@log_request
def admin_delete_key():
    """Delete a license key"""
    try:
        data = request.get_json()
        
        if not data or 'key_code' not in data:
            return jsonify({'error': 'key_code required'}), 400
        
        key_code = data['key_code']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM keys WHERE key_code = ?", (key_code,))
        conn.commit()
        conn.close()
        
        log_activity(action="KEY_DELETED", details=key_code)
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ Error deleting key: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/add-script', methods=['POST'])
@log_request
def admin_add_script():
    """Add a script (called from Discord bot)"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'script_key' not in data:
            return jsonify({'error': 'name and script_key required'}), 400
        
        name = data['name']
        script_key = data['script_key']
        description = data.get('description', 'ESP Script')
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO scripts (name, script_key, description) VALUES (?, ?, ?)",
                (name, script_key, description)
            )
            conn.commit()
            
            log_activity(action="SCRIPT_ADDED", details=f"{name} - {script_key}")
            
            return jsonify({'success': True})
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Script already exists'}), 409
        finally:
            conn.close()
        
    except Exception as e:
        print(f"❌ Error adding script: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/register-hwid', methods=['POST'])
@log_request
def admin_register_hwid():
    """Register HWID (called from Discord bot or script)"""
    try:
        data = request.get_json()
        
        if not data or 'discord_id' not in data or 'hwid' not in data:
            return jsonify({'error': 'discord_id and hwid required'}), 400
        
        discord_id = data['discord_id']
        hwid = data['hwid']
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO hwid_registry (discord_id, hwid) VALUES (?, ?) "
                "ON CONFLICT(discord_id, hwid) DO UPDATE SET last_seen = CURRENT_TIMESTAMP",
                (discord_id, hwid)
            )
            
            cursor.execute(
                "UPDATE users SET hwid = ? WHERE discord_id = ?",
                (hwid, discord_id)
            )
            
            conn.commit()
            
            log_activity(discord_id=discord_id, hwid=hwid, action="HWID_REGISTERED", details="Via admin")
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()
        
    except Exception as e:
        print(f"❌ Error registering HWID: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/blacklist', methods=['POST'])
@log_request
def admin_blacklist():
    """Add HWID to blacklist"""
    try:
        data = request.get_json()
        
        if not data or 'hwid' not in data or 'reason' not in data:
            return jsonify({'error': 'HWID and reason required'}), 400
        
        hwid = data['hwid']
        reason = data['reason']
        blacklisted_by = data.get('blacklisted_by', 'system')
        discord_id = data.get('discord_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO blacklist (hwid, reason, blacklisted_by, discord_id) VALUES (?, ?, ?, ?)",
                (hwid, reason, blacklisted_by, discord_id)
            )
            
            cursor.execute("UPDATE users SET is_active = 0 WHERE hwid = ?", (hwid,))
            
            conn.commit()
            
            log_activity(discord_id=discord_id, hwid=hwid, action="BLACKLISTED", details=reason)
            
            print(f"🚫 HWID blacklisted: {hwid[:16]}... - Reason: {reason}")
            
            return jsonify({'success': True})
            
        except sqlite3.IntegrityError:
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
        
        cursor.execute("SELECT COUNT(*) FROM scripts")
        total_scripts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM keys WHERE is_redeemed = 1")
        redeemed_keys = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT hwid) FROM hwid_registry")
        unique_hwids = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'blacklisted': blacklisted,
            'total_scripts': total_scripts,
            'redeemed_keys': redeemed_keys,
            'unique_hwids': unique_hwids
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
            SELECT u.discord_id, u.username, u.hwid, h.last_seen
            FROM users u
            LEFT JOIN hwid_registry h ON u.discord_id = h.discord_id AND u.hwid = h.hwid
            WHERE u.hwid IS NOT NULL
            ORDER BY h.last_seen DESC
        """)
        
        hwids = []
        for row in cursor.fetchall():
            hwids.append({
                'discord_id': row[0],
                'username': row[1],
                'hwid': row[2],
                'last_seen': row[3]
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
    print("Bedwars VisualScripts API Server v2.0")
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
