"""
Production API Server with Environment Variables
Supports .env file for local development and Render env vars for production
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

app = Flask(__name__)
CORS(app)

# =============================================
# CONFIGURATION FROM ENVIRONMENT VARIABLES
# =============================================
class Config:
    # API Server Settings
    DATABASE_PATH = os.getenv("DATABASE_PATH", "auth.db")
    PORT = int(os.getenv("PORT", 5000))
    HOST = os.getenv("HOST", "0.0.0.0")
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
    
    # Discord Integration
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    
    # Debug mode
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# Print config on startup (without secrets)
def print_config():
    print("=" * 50)
    print("Configuration:")
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
    """Initialize database with required tables"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
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
    
    # License keys table
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
    
    # Scripts table
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
    
    # Blacklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            blacklisted_by TEXT NOT NULL,
            roblox_username TEXT,
            roblox_userid TEXT,
            blacklisted_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Activity logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # HWID resets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hwid_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            reset_date TEXT DEFAULT CURRENT_TIMESTAMP,
            old_hwid TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def get_db():
    """Get database connection"""
    return sqlite3.connect(Config.DATABASE_PATH)

def hash_hwid(hwid):
    """Hash HWID using SHA256"""
    return hashlib.sha256(hwid.encode()).hexdigest()

def log_request(f):
    """Decorator to log API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if Config.DEBUG:
            print(f"📡 {request.method} {request.path} from {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

# =============================================
# ROUTES
# =============================================
@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'Bedwars VisualScripts API',
        'status': 'online',
        'version': '1.0.0',
        'endpoints': {
            'health': 'GET /health',
            'check_blacklist': 'POST /check-blacklist',
            'tamper_alert': 'POST /tamper-alert',
            'get_script': 'GET /script/<key>',
            'raw_script': 'GET /raw/<key>',
            'admin_stats': 'GET /admin/stats'
        }
    })

@app.route('/health', methods=['GET'])
@log_request
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'webhook': 'configured' if Config.DISCORD_WEBHOOK_URL else 'not_configured'
    })

@app.route('/check-blacklist', methods=['POST'])
@log_request
def check_blacklist():
    """Check if HWID is blacklisted"""
    try:
        data = request.get_json()
        
        if not data or 'hwid' not in data:
            return jsonify({'error': 'HWID required'}), 400
        
        hwid = data['hwid']
        hashed_hwid = hash_hwid(hwid)
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check raw HWID
        cursor.execute(
            "SELECT reason, blacklisted_at FROM blacklist WHERE hwid = ?",
            (hwid,)
        )
        result = cursor.fetchone()
        
        # Check hashed version
        if not result:
            cursor.execute(
                "SELECT b.reason, b.blacklisted_at FROM users u INNER JOIN blacklist b ON u.hwid = b.hwid WHERE u.hwid = ?",
                (hashed_hwid,)
            )
            result = cursor.fetchone()
        
        conn.close()
        
        if result:
            print(f"🚫 Blacklisted HWID detected: {hwid[:16]}...")
            return jsonify({
                'blacklisted': True,
                'reason': result[0],
                'blacklisted_at': result[1]
            })
        
        return jsonify({'blacklisted': False})
        
    except Exception as e:
        print(f"❌ Error checking blacklist: {e}")
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

@app.route('/script/<key>', methods=['GET'])
@log_request
def get_script_info(key):
    """Get script information"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT name, description, script_url, version FROM scripts WHERE script_key = ?",
            (key,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'found': True,
                'name': result[0],
                'description': result[1],
                'url': result[2],
                'version': result[3],
                'raw_url': f"{request.host_url}raw/{key}"
            })
        
        return jsonify({'found': False}), 404
        
    except Exception as e:
        print(f"❌ Error getting script: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/raw/<key>', methods=['GET'])
@log_request
def get_raw_script(key):
    """
    Get raw Lua script with auth key injected
    This is what users will use: script_key = "KEY"; loadstring(game:HttpGet("url"))()
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT script_content, script_url, name FROM scripts WHERE script_key = ?",
            (key,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            script_content = result[0]
            script_url = result[1]
            script_name = result[2]
            
            # If content is in database, inject the key and return
            if script_content:
                # Replace placeholder with actual key
                script_content = script_content.replace('SCRIPT_KEY = "PASTE-KEY-HERE"', f'SCRIPT_KEY = "{key}"')
                script_content = script_content.replace('script_key = "PUT_YOUR_KEY_HERE"', f'script_key = "{key}"')
                return script_content, 200, {'Content-Type': 'text/plain'}
            
            # If URL is provided, redirect
            elif script_url:
                return jsonify({
                    'message': 'Script hosted externally',
                    'url': script_url
                }), 200
            
            # Default: Return ESP script with injected key
            else:
                # Load ESP script template
                esp_script_path = os.path.join(os.path.dirname(__file__), 'esp-script.lua')
                if os.path.exists(esp_script_path):
                    with open(esp_script_path, 'r') as f:
                        esp_content = f.read()
                    # Inject the key
                    esp_content = esp_content.replace('SCRIPT_KEY = "PASTE-KEY-HERE"', f'SCRIPT_KEY = "{key}"')
                    return esp_content, 200, {'Content-Type': 'text/plain'}
                else:
                    return f'-- ESP Script for {script_name}\n-- Key: {key}\nprint("✅ Script loaded!")', 200, {'Content-Type': 'text/plain'}
        
        return "-- Invalid script key", 404, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        print(f"❌ Error getting raw script: {e}")
        return f"-- Error: {str(e)}", 500, {'Content-Type': 'text/plain'}

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
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO blacklist (hwid, reason, blacklisted_by) VALUES (?, ?, ?)",
                (hwid, reason, blacklisted_by)
            )
            
            hashed = hash_hwid(hwid)
            cursor.execute("UPDATE users SET is_active = 0 WHERE hwid = ?", (hashed,))
            
            conn.commit()
            print(f"🚫 HWID blacklisted: {hwid[:16]}...")
            
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
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'blacklisted': blacklisted,
            'total_scripts': total_scripts,
            'redeemed_keys': redeemed_keys
        })
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
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
    print("Bedwars VisualScripts API Server")
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
