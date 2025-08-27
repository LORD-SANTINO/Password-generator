import requests
import secrets
import string
import re
import json
import os
from typing import Dict, List, Tuple
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from datetime import datetime

# Configuration
TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
DATA_FILE = "password_data.json"
KEY_FILE = "secret.key"
STATS_FILE = "bot_stats.json"  # New file for statistics

# Load or generate encryption key
def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Initialize encryption
fernet = Fernet(get_encryption_key())

# Load user data
def load_user_data() -> Dict[str, Dict[str, str]]:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                encrypted_data = json.load(f)
                # Decrypt the data
                decrypted_data = {}
                for user_id, user_entries in encrypted_data.items():
                    decrypted_data[user_id] = {}
                    for service, encrypted_password in user_entries.items():
                        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                        decrypted_data[user_id][service] = decrypted_password
                return decrypted_data
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

# Save user data
def save_user_data(data: Dict[str, Dict[str, str]]):
    # Encrypt the data before saving
    encrypted_data = {}
    for user_id, user_entries in data.items():
        encrypted_data[user_id] = {}
        for service, password in user_entries.items():
            encrypted_password = fernet.encrypt(password.encode()).decode()
            encrypted_data[user_id][service] = encrypted_password
    
    with open(DATA_FILE, 'w') as f:
        json.dump(encrypted_data, f, indent=2)

# Load or create stats data
def load_stats_data():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"total_users": 0, "active_users": 0, "user_join_dates": {}, "total_commands": 0}
    return {"total_users": 0, "active_users": 0, "user_join_dates": {}, "total_commands": 0}

# Save stats data
def save_stats_data(stats_data):
    with open(STATS_FILE, 'w') as f:
        json.dump(stats_data, f, indent=2)

# Load existing data
user_passwords = load_user_data()
bot_stats = load_stats_data()

# Migrate existing users from password data to stats
def migrate_existing_users():
    global bot_stats
    
    for user_id in user_passwords.keys():
        if user_id not in bot_stats["user_join_dates"]:
            bot_stats["total_users"] += 1
            bot_stats["user_join_dates"][user_id] = {
                "first_seen": datetime.now().isoformat(),
                "username": f"User_{user_id}",
                "last_seen": datetime.now().isoformat(),
                "usage_count": 1
            }
    
    bot_stats["active_users"] = len(bot_stats["user_join_dates"])
    save_stats_data(bot_stats)

# Track user usage
async def track_usage(update: Update):
    user_id = str(update.effective_user.id)
    user_name = update.effective_user.first_name or f"User_{user_id}"
    
    if user_id not in bot_stats["user_join_dates"]:
        bot_stats["total_users"] += 1
        bot_stats["user_join_dates"][user_id] = {
            "first_seen": datetime.now().isoformat(),
            "username": user_name,
            "last_seen": datetime.now().isoformat(),
            "usage_count": 0
        }
    
    bot_stats["user_join_dates"][user_id]["last_seen"] = datetime.now().isoformat()
    bot_stats["user_join_dates"][user_id]["username"] = user_name
    bot_stats["user_join_dates"][user_id]["usage_count"] += 1
    bot_stats["active_users"] = len(bot_stats["user_join_dates"])
    bot_stats["total_commands"] += 1
    save_stats_data(bot_stats)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    await track_usage(update)
    
    welcome_text = """
    🔐 *Password Manager Bot*
    
    *I help you manage passwords securely!*
    
    *Available Commands:*
    /generate - Create a strong random password
    /passphrase - Generate a memorable passphrase
    /strength - Check how strong your password is
    /breach - Check if password was in a data breach
    /save - Store a password for a service
    /get - Retrieve a stored password
    /list - Show all your stored services
    /delete - Remove a stored password
    /stats - View bot statistics (Admin only)
    
    *All passwords are encrypted before storage!*
    """
    await update.message.reply_text(welcome_text, parse_mode='Markdown')

async def generate_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate a strong random password"""
    await track_usage(update)
    
    length = 16
    if context.args and context.args[0].isdigit():
        length = max(12, min(int(context.args[0]), 32))  # Limit between 12-32 chars
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    await update.message.reply_text(
        f"🔒 *Generated Password:*\n`{password}`\n\n"
        f"*Length:* {length} characters\n"
        "*Strength:* Very Strong 💪",
        parse_mode='Markdown'
    )

async def generate_passphrase(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate a memorable passphrase"""
    await track_usage(update)
    
    words = [
        'apple', 'banana', 'carrot', 'dragon', 'elephant', 'flamingo', 'giraffe', 
        'honey', 'iguana', 'jaguar', 'koala', 'lemon', 'mango', 'narwhal',
        'orange', 'panda', 'quail', 'raccoon', 'strawberry', 'tiger', 'umbrella',
        'vulture', 'watermelon', 'xylophone', 'yak', 'zebra'
    ]
    
    passphrase = '-'.join(secrets.choice(words) for _ in range(4))
    passphrase_with_numbers = passphrase + str(secrets.randbelow(100))
    
    await update.message.reply_text(
        f"🔐 *Generated Passphrase:*\n`{passphrase_with_numbers}`\n\n"
        "*Easy to remember, hard to guess!* 🧠",
        parse_mode='Markdown'
    )

async def check_strength(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check password strength"""
    await track_usage(update)
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a password to check.\nExample: /strength mypassword123")
        return
    
    password = ' '.join(context.args)
    strength = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        strength += 2
        feedback.append("✅ Good length (12+ characters)")
    elif len(password) >= 8:
        strength += 1
        feedback.append("⚠️  Medium length (8-11 characters)")
    else:
        feedback.append("❌ Too short (less than 8 characters)")
    
    # Complexity checks
    if re.search(r'[A-Z]', password):
        strength += 1
        feedback.append("✅ Contains uppercase letters")
    if re.search(r'[a-z]', password):
        strength += 1
        feedback.append("✅ Contains lowercase letters")
    if re.search(r'[0-9]', password):
        strength += 1
        feedback.append("✅ Contains numbers")
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 2
        feedback.append("✅ Contains special characters")
    
    # Strength rating
    if strength >= 6:
        rating = "Very Strong 💪"
    elif strength >= 4:
        rating = "Strong 👍"
    elif strength >= 2:
        rating = "Medium 😐"
    else:
        rating = "Weak 👎"
    
    feedback_text = "\n".join(feedback)
    await update.message.reply_text(
        f"🔍 *Password Strength Analysis:*\n\n"
        f"*Password:* `{password}`\n"
        f"*Rating:* {rating}\n\n"
        f"*Details:*\n{feedback_text}",
        parse_mode='Markdown'
    )

async def check_breach(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check if password was in a data breach using HaveIBeenPwned API"""
    await track_usage(update)
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a password to check.\nExample: /breach mypassword123")
        return
    
    password = ' '.join(context.args)
    
    # Hash the password (SHA-1)
    sha1_hash = hashes.Hash(hashes.SHA1())
    sha1_hash.update(password.encode())
    password_hash = sha1_hash.finalize().hex().upper()
    
    # Check first 5 chars against HIBP API
    prefix, suffix = password_hash[:5], password_hash[5:]
    
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if response.status_code == 200:
            hashes_list = response.text.splitlines()
            for h in hashes_list:
                if h.startswith(suffix):
                    count = int(h.split(':')[1])
                    await update.message.reply_text(
                        f"🚨 *Password Breached!*\n\n"
                        f"This password appears in *{count}* known data breaches.\n\n"
                        f"*Recommendation:* Change it immediately! Use /generate to create a new one.",
                        parse_mode='Markdown'
                    )
                    return
            
            await update.message.reply_text(
                f"✅ *No breaches found!*\n\n"
                f"This password hasn't been found in any known data breaches.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text("❌ Could not check breaches. API might be down.")
    except requests.RequestException:
        await update.message.reply_text("❌ Network error. Could not check breaches.")

async def save_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Save a password for a service"""
    await track_usage(update)
    
    if len(context.args) < 2:
        await update.message.reply_text("❌ Usage: /save <service> <password>\nExample: /save gmail MyStrongPass123!")
        return
    
    service = context.args[0].lower()
    password = ' '.join(context.args[1:])
    user_id = str(update.effective_user.id)
    
    # Initialize user entry if not exists
    if user_id not in user_passwords:
        user_passwords[user_id] = {}
    
    # Save the password
    user_passwords[user_id][service] = password
    save_user_data(user_passwords)
    
    await update.message.reply_text(
        f"✅ *Password saved!*\n\n"
        f"*Service:* {service}\n"
        f"*Password:* `{password}`\n\n"
        f"Use /get {service} to retrieve it later.",
        parse_mode='Markdown'
    )

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Retrieve a stored password"""
    await track_usage(update)
    
    if not context.args:
        await update.message.reply_text("❌ Usage: /get <service>\nExample: /get gmail")
        return
    
    service = context.args[0].lower()
    user_id = str(update.effective_user.id)
    
    if user_id not in user_passwords or service not in user_passwords[user_id]:
        await update.message.reply_text(f"❌ No password found for service: {service}")
        return
    
    password = user_passwords[user_id][service]
    await update.message.reply_text(
        f"🔓 *Password for {service}:*\n`{password}`",
        parse_mode='Markdown'
    )

async def list_services(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List all stored services"""
    await track_usage(update)
    
    user_id = str(update.effective_user.id)
    
    if user_id not in user_passwords or not user_passwords[user_id]:
        await update.message.reply_text("❌ You haven't saved any passwords yet.")
        return
    
    services = list(user_passwords[user_id].keys())
    services_text = "\n".join([f"• {service}" for service in services])
    
    await update.message.reply_text(
        f"📋 *Your stored services:*\n\n{services_text}\n\n"
        f"Use /get <service> to retrieve a password.",
        parse_mode='Markdown'
    )

async def delete_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Delete a stored password"""
    await track_usage(update)
    
    if not context.args:
        await update.message.reply_text("❌ Usage: /delete <service>\nExample: /delete gmail")
        return
    
    service = context.args[0].lower()
    user_id = str(update.effective_user.id)
    
    if user_id not in user_passwords or service not in user_passwords[user_id]:
        await update.message.reply_text(f"❌ No password found for service: {service}")
        return
    
    # Delete the password
    del user_passwords[user_id][service]
    
    # Remove user entry if no passwords left
    if not user_passwords[user_id]:
        del user_passwords[user_id]
    
    save_user_data(user_passwords)
    
    await update.message.reply_text(f"✅ Deleted password for: {service}")

async def show_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot statistics (Admin only)"""
    await track_usage(update)
    
    user_id = str(update.effective_user.id)
    
    ADMIN_IDS = ["7243305432"]  # Example: ["123456789", "987654321"]
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ This command is for administrators only.")
        return
    
    # Calculate statistics
    total_users = bot_stats["total_users"]
    active_users = bot_stats["active_users"]
    total_commands = bot_stats["total_commands"]
    
    # Calculate average usage
    total_usage = sum(user_data["usage_count"] for user_data in bot_stats["user_join_dates"].values())
    avg_usage = total_usage / active_users if active_users > 0 else 0
    
    # Find most active user
    most_active = max(bot_stats["user_join_dates"].items(), key=lambda x: x[1]["usage_count"], default=(None, {}))
    
    # Get join dates sorted
    sorted_users = sorted(bot_stats["user_join_dates"].items(), key=lambda x: x[1]["first_seen"])
    
    # Prepare statistics message
    stats_text = f"""
📊 *Bot Statistics*

👥 *Users:*
• Total Users: {total_users}
• Active Users: {active_users}
• Total Commands: {total_commands}
• Avg. Usage per User: {avg_usage:.1f}

🏆 *Most Active User:*
• {most_active[1]['username'] if most_active[0] else 'N/A'}
• Usage Count: {most_active[1].get('usage_count', 0) if most_active[0] else 0}

📅 *Recent Users (first 10):*
"""
    
    # Add first 10 users by join date
    for i, (user_id, user_data) in enumerate(sorted_users[:10]):
        join_date = datetime.fromisoformat(user_data["first_seen"]).strftime("%Y-%m-%d")
        stats_text += f"{i+1}. {user_data['username']} - {join_date} ({user_data['usage_count']} uses)\n"
    
    if len(sorted_users) > 10:
        stats_text += f"\n... and {len(sorted_users) - 10} more users"
    
    await update.message.reply_text(stats_text, parse_mode='Markdown')

def main():
    """Start the bot"""
    # Migrate existing users first
    migrate_existing_users()
    
    application = Application.builder().token(TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("generate", generate_password))
    application.add_handler(CommandHandler("passphrase", generate_passphrase))
    application.add_handler(CommandHandler("strength", check_strength))
    application.add_handler(CommandHandler("breach", check_breach))
    application.add_handler(CommandHandler("save", save_password))
    application.add_handler(CommandHandler("get", get_password))
    application.add_handler(CommandHandler("list", list_services))
    application.add_handler(CommandHandler("delete", delete_password))
    application.add_handler(CommandHandler("stats", show_stats))  # Add stats command
    
    print("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()
