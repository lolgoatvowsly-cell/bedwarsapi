"""
Discord Bot with Environment Variables Support
All configuration through .env file or environment variables
"""

import discord
from discord import app_commands
from discord.ext import commands
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================
# CONFIGURATION FROM ENVIRONMENT
# =============================================
class Config:
    # Discord Bot
    BOT_TOKEN = os.getenv("BOT_TOKEN")
    GUILD_ID = int(os.getenv("GUILD_ID", 0))
    
    # Role IDs
    ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", 0))
    BUYER_ROLE_ID = int(os.getenv("BUYER_ROLE_ID", 0))
    
    # Webhook for tamper alerts
    TAMPER_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    
    # Settings
    HWID_RESET_COOLDOWN_DAYS = int(os.getenv("HWID_RESET_COOLDOWN_DAYS", 7))
    DATABASE_PATH = os.getenv("DATABASE_PATH", "auth.db")
    
    # Panel customization
    PANEL_TITLE = os.getenv("PANEL_TITLE", "Bedwars VisualScripts Panel")
    PANEL_COLOR = int(os.getenv("PANEL_COLOR", "0x5865F2"), 16)
    
    # API Server (optional)
    API_URL = os.getenv("API_URL", "")

# Validate configuration
def validate_config():
    errors = []
    
    if not Config.BOT_TOKEN:
        errors.append("BOT_TOKEN not set")
    if Config.GUILD_ID == 0:
        errors.append("GUILD_ID not set")
    if Config.ADMIN_ROLE_ID == 0:
        errors.append("ADMIN_ROLE_ID not set (optional but recommended)")
    if Config.BUYER_ROLE_ID == 0:
        errors.append("BUYER_ROLE_ID not set (optional but recommended)")
    
    if errors:
        print("=" * 50)
        print("⚠️  CONFIGURATION ERRORS:")
        print("=" * 50)
        for error in errors:
            print(f"❌ {error}")
        print("=" * 50)
        print("Please set these in your .env file or environment variables")
        return False
    
    return True

# Print configuration (without secrets)
def print_config():
    print("=" * 50)
    print("Bot Configuration:")
    print("=" * 50)
    print(f"Guild ID: {Config.GUILD_ID}")
    print(f"Admin Role ID: {Config.ADMIN_ROLE_ID or 'Not set'}")
    print(f"Buyer Role ID: {Config.BUYER_ROLE_ID or 'Not set'}")
    print(f"Database: {Config.DATABASE_PATH}")
    print(f"HWID Reset Cooldown: {Config.HWID_RESET_COOLDOWN_DAYS} days")
    print(f"Panel Title: {Config.PANEL_TITLE}")
    print(f"Tamper Webhook: {'✅ Configured' if Config.TAMPER_WEBHOOK_URL else '❌ Not set'}")
    print(f"API URL: {Config.API_URL or 'Not set'}")
    print("=" * 50)

# =============================================
# DATABASE SETUP
# =============================================
class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        conn = self.get_connection()
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
                roblox_username TEXT,
                roblox_userid TEXT,
                blacklisted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
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

# =============================================
# UTILITY FUNCTIONS
# =============================================
def generate_key(length=32):
    characters = string.ascii_uppercase + string.digits
    key = ''.join(secrets.choice(characters) for _ in range(length))
    return '-'.join([key[i:i+8] for i in range(0, len(key), 8)])

def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

def log_activity(db: Database, discord_id: str, action: str, details: str = ""):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO activity_logs (discord_id, action, details) VALUES (?, ?, ?)",
        (discord_id, action, details)
    )
    conn.commit()
    conn.close()

def is_admin(interaction: discord.Interaction) -> bool:
    if Config.ADMIN_ROLE_ID == 0:
        return interaction.user.guild_permissions.administrator
    return (interaction.user.guild_permissions.administrator or 
            any(role.id == Config.ADMIN_ROLE_ID for role in interaction.user.roles))

def has_buyer_role(interaction: discord.Interaction) -> bool:
    if Config.BUYER_ROLE_ID == 0:
        return True  # If not configured, allow everyone
    return any(role.id == Config.BUYER_ROLE_ID for role in interaction.user.roles)

# =============================================
# DISCORD BOT SETUP
# =============================================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)
db = Database(Config.DATABASE_PATH)

# =============================================
# PANEL VIEW
# =============================================
class PanelView(discord.ui.View):
    def __init__(self, user_id: str):
        super().__init__(timeout=None)
        self.user_id = user_id
    
    @discord.ui.button(label="🔑 Redeem Key", style=discord.ButtonStyle.success)
    async def redeem_key_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_buyer_role(interaction):
            await interaction.response.send_message(
                "❌ You need the Buyer role to use this panel!",
                ephemeral=True
            )
            return
        
        modal = RedeemKeyModal()
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="📜 Get Script", style=discord.ButtonStyle.primary)
    async def get_script_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_buyer_role(interaction):
            await interaction.response.send_message(
                "❌ You need the Buyer role to use this panel!",
                ephemeral=True
            )
            return
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE discord_id = ?", (str(interaction.user.id),))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not user[5]:
            await interaction.response.send_message(
                "❌ You don't have an active subscription! Redeem a key first.",
                ephemeral=True
            )
            return
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name, description, script_url, script_key, version FROM scripts")
        scripts = cursor.fetchall()
        conn.close()
        
        if not scripts:
            await interaction.response.send_message(
                "📝 No scripts available yet.",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="📜 Available Scripts",
            description="Here are your scripts:",
            color=Config.PANEL_COLOR
        )
        
        for script in scripts:
            name, desc, url, key, version = script
            api_url = Config.API_URL or "https://your-app.onrender.com"
            embed.add_field(
                name=f"{name} (v{version})",
                value=f"{desc}\n\n**Key:** `{key}`\n**Usage:**\n```lua\ngetgenv().scriptkey = \"{key}\"\nloadstring(game:HttpGet(\"{url or api_url + '/raw/' + key}\"))()\n```",
                inline=False
            )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
    @discord.ui.button(label="🔄 Reset HWID", style=discord.ButtonStyle.secondary)
    async def reset_hwid_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_buyer_role(interaction):
            await interaction.response.send_message(
                "❌ You need the Buyer role!",
                ephemeral=True
            )
            return
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hwid, last_reset FROM users WHERE discord_id = ?", (str(interaction.user.id),))
        result = cursor.fetchone()
        
        if not result or not result[0]:
            await interaction.response.send_message(
                "❌ No HWID registered to reset.",
                ephemeral=True
            )
            conn.close()
            return
        
        hwid, last_reset = result
        
        if last_reset:
            last_reset_date = datetime.fromisoformat(last_reset)
            days_since = (datetime.now() - last_reset_date).days
            
            if days_since < Config.HWID_RESET_COOLDOWN_DAYS:
                days_left = Config.HWID_RESET_COOLDOWN_DAYS - days_since
                await interaction.response.send_message(
                    f"❌ You can reset your HWID again in {days_left} days.",
                    ephemeral=True
                )
                conn.close()
                return
        
        cursor.execute(
            "INSERT INTO hwid_resets (discord_id, old_hwid) VALUES (?, ?)",
            (str(interaction.user.id), hwid)
        )
        
        cursor.execute(
            "UPDATE users SET hwid = NULL, last_reset = ? WHERE discord_id = ?",
            (datetime.now().isoformat(), str(interaction.user.id))
        )
        
        conn.commit()
        conn.close()
        
        log_activity(db, str(interaction.user.id), "HWID_RESET", "via panel")
        
        embed = discord.Embed(
            title="✅ HWID Reset Successful",
            description="Your HWID has been reset.",
            color=0x00ff00
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
    @discord.ui.button(label="📊 Get Stats", style=discord.ButtonStyle.secondary)
    async def get_stats_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_buyer_role(interaction):
            await interaction.response.send_message(
                "❌ You need the Buyer role!",
                ephemeral=True
            )
            return
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE discord_id = ?", (str(interaction.user.id),))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            await interaction.response.send_message(
                "❌ You are not registered. Redeem a key first!",
                ephemeral=True
            )
            return
        
        _, discord_id, username, hwid, license_key, is_active, expiry_date, created_at, last_reset = user
        
        is_expired = False
        if expiry_date:
            is_expired = datetime.fromisoformat(expiry_date) < datetime.now()
        
        status = "✅ Active" if is_active and not is_expired else "❌ Inactive/Expired"
        
        embed = discord.Embed(
            title="📊 Your Account Statistics",
            color=0x00ff00 if is_active and not is_expired else 0xff0000
        )
        
        embed.add_field(name="Username", value=username, inline=True)
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="HWID", value="✅ Yes" if hwid else "❌ No", inline=True)
        embed.add_field(name="License Key", value=license_key or "N/A", inline=True)
        embed.add_field(
            name="Expiry",
            value=datetime.fromisoformat(expiry_date).strftime("%Y-%m-%d") if expiry_date else "N/A",
            inline=True
        )
        embed.add_field(
            name="Created",
            value=datetime.fromisoformat(created_at).strftime("%Y-%m-%d"),
            inline=True
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

# =============================================
# MODALS
# =============================================
class RedeemKeyModal(discord.ui.Modal, title="Redeem License Key"):
    key_input = discord.ui.TextInput(
        label="License Key",
        placeholder="XXXX-XXXX-XXXX-XXXX",
        required=True,
        max_length=50
    )
    
    async def on_submit(self, interaction: discord.Interaction):
        key_code = self.key_input.value.upper().strip()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT duration_days FROM keys WHERE key_code = ? AND is_redeemed = 0",
            (key_code,)
        )
        key_data = cursor.fetchone()
        
        if not key_data:
            await interaction.response.send_message(
                "❌ Invalid or already redeemed key!",
                ephemeral=True
            )
            conn.close()
            return
        
        duration_days = key_data[0]
        expiry_date = (datetime.now() + timedelta(days=duration_days)).isoformat()
        
        cursor.execute("SELECT id FROM users WHERE discord_id = ?", (str(interaction.user.id),))
        user_exists = cursor.fetchone()
        
        if user_exists:
            cursor.execute(
                "UPDATE users SET license_key = ?, expiry_date = ?, is_active = 1 WHERE discord_id = ?",
                (key_code, expiry_date, str(interaction.user.id))
            )
        else:
            cursor.execute(
                "INSERT INTO users (discord_id, username, license_key, expiry_date, is_active) VALUES (?, ?, ?, ?, 1)",
                (str(interaction.user.id), interaction.user.name, key_code, expiry_date)
            )
        
        cursor.execute(
            "UPDATE keys SET is_redeemed = 1, redeemed_by = ?, redeemed_at = ? WHERE key_code = ?",
            (str(interaction.user.id), datetime.now().isoformat(), key_code)
        )
        
        conn.commit()
        conn.close()
        
        log_activity(db, str(interaction.user.id), "REDEEM_KEY", f"Key: {key_code}")
        
        if Config.BUYER_ROLE_ID:
            try:
                role = interaction.guild.get_role(Config.BUYER_ROLE_ID)
                if role and role not in interaction.user.roles:
                    await interaction.user.add_roles(role)
            except:
                pass
        
        embed = discord.Embed(
            title="🎉 Key Redeemed Successfully",
            color=0x00ff00
        )
        embed.add_field(name="Key", value=key_code, inline=True)
        embed.add_field(name="Duration", value=f"{duration_days} days", inline=True)
        embed.add_field(
            name="Expires",
            value=datetime.fromisoformat(expiry_date).strftime("%Y-%m-%d"),
            inline=True
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

# =============================================
# SLASH COMMANDS
# =============================================
@bot.event
async def on_ready():
    print("=" * 50)
    print(f"✅ Bot logged in as {bot.user}")
    print(f"✅ Connected to {len(bot.guilds)} guild(s)")
    print("=" * 50)
    
    try:
        synced = await bot.tree.sync(guild=discord.Object(id=Config.GUILD_ID))
        print(f"✅ Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"❌ Failed to sync commands: {e}")

@bot.tree.command(
    name="panel",
    description="Open the control panel",
    guild=discord.Object(id=Config.GUILD_ID)
)
async def panel_command(interaction: discord.Interaction):
    if not has_buyer_role(interaction):
        await interaction.response.send_message(
            "❌ You need the Buyer role to access the panel!",
            ephemeral=True
        )
        return
    
    embed = discord.Embed(
        title=Config.PANEL_TITLE,
        description=f"This control panel is for the project: **{Config.PANEL_TITLE}**\n\n"
                    f"If you're a buyer, click on the buttons below to redeem your key, get the script or get your role\n\n"
                    f"**Sent by {interaction.user.mention}** • {datetime.now().strftime('%d/%m/%Y, %H:%M')}",
        color=Config.PANEL_COLOR
    )
    
    view = PanelView(str(interaction.user.id))
    
    await interaction.response.send_message(embed=embed, view=view)

@bot.tree.command(
    name="whitelist",
    description="Whitelist a user and give them the Buyer role",
    guild=discord.Object(id=Config.GUILD_ID)
)
@app_commands.describe(user="The user to whitelist")
async def whitelist_command(interaction: discord.Interaction, user: discord.Member):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "❌ You don't have permission to use this command!",
            ephemeral=True
        )
        return
    
    if Config.BUYER_ROLE_ID == 0:
        await interaction.response.send_message(
            "❌ BUYER_ROLE_ID not configured in environment variables!",
            ephemeral=True
        )
        return
    
    role = interaction.guild.get_role(Config.BUYER_ROLE_ID)
    
    if not role:
        await interaction.response.send_message(
            "❌ Buyer role not found!",
            ephemeral=True
        )
        return
    
    try:
        await user.add_roles(role)
        
        log_activity(db, str(interaction.user.id), "WHITELIST_USER", f"Whitelisted: {user.name}")
        
        embed = discord.Embed(
            title="✅ User Whitelisted",
            description=f"{user.mention} has been whitelisted!",
            color=0x00ff00
        )
        embed.add_field(name="User", value=user.mention, inline=True)
        embed.add_field(name="By", value=interaction.user.mention, inline=True)
        
        await interaction.response.send_message(embed=embed)
        
        try:
            dm_embed = discord.Embed(
                title="🎉 You've been whitelisted!",
                description=f"You've been given access to **{Config.PANEL_TITLE}**!\n\nUse `/panel` in the server.",
                color=Config.PANEL_COLOR
            )
            await user.send(embed=dm_embed)
        except:
            pass
        
    except Exception as e:
        await interaction.response.send_message(
            f"❌ Error: {e}",
            ephemeral=True
        )

@bot.tree.command(
    name="genkey",
    description="Generate license keys [ADMIN]",
    guild=discord.Object(id=Config.GUILD_ID)
)
@app_commands.describe(duration="Duration in days", amount="Number of keys")
async def genkey_command(interaction: discord.Interaction, duration: int = 30, amount: int = 1):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "❌ Admin only!",
            ephemeral=True
        )
        return
    
    if amount > 20:
        await interaction.response.send_message(
            "❌ Max 20 keys!",
            ephemeral=True
        )
        return
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    keys = []
    for _ in range(amount):
        key = generate_key()
        cursor.execute(
            "INSERT INTO keys (key_code, duration_days) VALUES (?, ?)",
            (key, duration)
        )
        keys.append(key)
    
    conn.commit()
    conn.close()
    
    log_activity(db, str(interaction.user.id), "GEN_KEYS", f"{amount}x{duration}d")
    
    embed = discord.Embed(
        title="🔑 Keys Generated",
        description=f"```\n" + "\n".join(keys) + "\n```",
        color=0x00ff00
    )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(
    name="genscript",
    description="Generate script key [ADMIN]",
    guild=discord.Object(id=Config.GUILD_ID)
)
@app_commands.describe(name="Script name", url="Script URL (optional)")
async def genscript_command(interaction: discord.Interaction, name: str, url: str = ""):
    if not is_admin(interaction):
        await interaction.response.send_message(
            "❌ Admin only!",
            ephemeral=True
        )
        return
    
    script_key = generate_key()
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO scripts (name, script_key, script_url) VALUES (?, ?, ?)",
            (name, script_key, url)
        )
        conn.commit()
        
        log_activity(db, str(interaction.user.id), "GEN_SCRIPT", f"{name}")
        
        api_url = Config.API_URL or "https://your-app.onrender.com"
        
        embed = discord.Embed(
            title="📜 Script Key Generated",
            color=0x00ff00
        )
        embed.add_field(name="Name", value=name, inline=True)
        embed.add_field(name="Key", value=f"`{script_key}`", inline=False)
        embed.add_field(name="URL", value=url or f"{api_url}/raw/{script_key}", inline=False)
        embed.set_footer(text="⚠️ Hardcode this key into your Lua script!")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
    except sqlite3.IntegrityError:
        await interaction.response.send_message(
            "❌ Script already exists!",
            ephemeral=True
        )
    finally:
        conn.close()

@bot.tree.command(
    name="stats",
    description="View system statistics",
    guild=discord.Object(id=Config.GUILD_ID)
)
async def stats_command(interaction: discord.Interaction):
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
    active = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM blacklist")
    blacklisted = cursor.fetchone()[0]
    
    conn.close()
    
    embed = discord.Embed(
        title="📊 Statistics",
        color=Config.PANEL_COLOR
    )
    embed.add_field(name="Users", value=str(total), inline=True)
    embed.add_field(name="Active", value=str(active), inline=True)
    embed.add_field(name="Blacklisted", value=str(blacklisted), inline=True)
    
    await interaction.response.send_message(embed=embed)

# =============================================
# RUN BOT
# =============================================
if __name__ == "__main__":
    print("=" * 50)
    print("Discord Authentication Bot")
    print("=" * 50)
    
    print_config()
    
    if not validate_config():
        exit(1)
    
    print("Starting bot...")
    bot.run(Config.BOT_TOKEN)
