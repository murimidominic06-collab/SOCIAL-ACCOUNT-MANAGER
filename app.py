import os
import re
import hmac
import time
import secrets
import sqlite3
import threading
from datetime import datetime
from functools import wraps
from pathlib import Path

import requests
from flask import (
    Flask, abort, flash, has_request_context, redirect,
    render_template_string, request, session, url_for
)
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

# Optional: load secrets from a .env file if python-dotenv is installed.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "users.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "local-development-only-change-before-deployment"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP development only
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

PLATFORMS = ["Facebook", "WhatsApp", "Instagram", "TikTok", "Telegram"]


# ======================================================================
# DATABASE
# ======================================================================

def get_db():
    db = sqlite3.connect(str(DATABASE))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS social_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                account_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Not connected',
                UNIQUE(user_id, platform),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                send_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                detail TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS message_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                ok INTEGER NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)


init_db()


def set_status(platform, status, label=""):
    """Save a platform's status for the logged-in user."""
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO social_accounts
               (user_id, platform, account_name, status)
               VALUES (?, ?, '', 'Not connected')""",
            (session["user_id"], platform),
        )
        db.execute(
            """UPDATE social_accounts SET status = ?, account_name = ?
               WHERE user_id = ? AND platform = ?""",
            (status, label or "", session["user_id"], platform),
        )


def log_message(platform, target, message, ok, detail, source, user_id=None):
    """Record a sent message in the history table. Never raises."""
    try:
        if user_id is None and has_request_context():
            user_id = session.get("user_id")
        if user_id is None:
            return
        with get_db() as db:
            db.execute(
                """INSERT INTO message_log
                   (user_id, platform, target, message, ok, detail, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, platform, str(target), message,
                 1 if ok else 0, str(detail)[:300], source),
            )
    except Exception as exc:
        print("Log error:", type(exc).__name__)


# ======================================================================
# SECURITY
# ======================================================================

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        saved = session.get("csrf_token", "")
        if not sent or not saved or not hmac.compare_digest(sent, saved):
            abort(400, description="Your form session expired. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ======================================================================
# WHATSAPP CLOUD API
# ======================================================================

def wa_config():
    return (
        os.environ.get("WA_ACCESS_TOKEN", "").strip(),
        os.environ.get("WA_PHONE_NUMBER_ID", "").strip(),
        os.environ.get("WA_API_VERSION", "v22.0").strip() or "v22.0",
    )


def wa_check():
    """Return (ok, details, display_phone, verified_name)."""
    token, phone_id, version = wa_config()
    if not token or not phone_id:
        return False, "WA_ACCESS_TOKEN or WA_PHONE_NUMBER_ID is not set.", "", ""
    if not re.fullmatch(r"v\d+\.\d+", version):
        return False, "WA_API_VERSION must look like v22.0.", "", ""
    if not phone_id.isdigit():
        return False, "WA_PHONE_NUMBER_ID must be numeric.", "", ""
    try:
        r = requests.get(
            f"https://graph.facebook.com/{version}/{phone_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"fields": "display_phone_number,verified_name"},
            timeout=15,
        )
        data = r.json()
    except requests.RequestException:
        return False, "Could not reach Meta. Check your internet connection.", "", ""
    except ValueError:
        return False, "Meta returned an unreadable response.", "", ""
    if r.ok and not data.get("error"):
        return (True, "WhatsApp Cloud API access verified.",
                data.get("display_phone_number", ""), data.get("verified_name", ""))
    msg = (data.get("error") or {}).get("message", f"Meta returned HTTP {r.status_code}.")
    return False, msg, "", ""


def wa_send(recipient, message):
    """Send a text message. Return (ok, details)."""
    token, phone_id, version = wa_config()
    if not token or not phone_id:
        return False, "WhatsApp credentials are not set."
    to = re.sub(r"\D", "", recipient or "")
    if not 8 <= len(to) <= 15:
        return False, "Enter the number with country code, digits only (e.g. 2547XXXXXXXX)."
    try:
        r = requests.post(
            f"https://graph.facebook.com/{version}/{phone_id}/messages",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "messaging_product": "whatsapp",
                "to": to,
                "type": "text",
                "text": {"body": message},
            },
            timeout=20,
        )
        data = r.json()
    except requests.RequestException:
        return False, "Could not reach Meta."
    except ValueError:
        return False, "Meta returned an unreadable response."
    if r.ok and not data.get("error"):
        return True, "Message accepted by WhatsApp."
    return False, (data.get("error") or {}).get("message", f"HTTP {r.status_code}")


# ======================================================================
# TELEGRAM BOT API
# ======================================================================

def tg_call(method, payload=None):
    """Return (ok, result_or_error_text)."""
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    if not token:
        return False, "TG_BOT_TOKEN is not set."
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/{method}",
            json=payload or {},
            timeout=20,
        )
        data = r.json()
    except requests.RequestException:
        return False, "Could not reach Telegram."
    except ValueError:
        return False, "Telegram returned an unreadable response."
    if data.get("ok"):
        return True, data.get("result")
    return False, data.get("description", f"HTTP {r.status_code}")


def tg_recent_chats():
    ok, result = tg_call("getUpdates")
    chats = {}
    if ok and isinstance(result, list):
        for update in result:
            msg = update.get("message") or {}
            chat = msg.get("chat") or {}
            if chat.get("id"):
                name = " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")])) \
                    or chat.get("title") or chat.get("username") or "Unknown"
                chats[chat["id"]] = name
    return chats


# ======================================================================
# LAYOUT
# ======================================================================

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} | Social Media Manager</title>
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Arial, sans-serif; background: #f3f6fb; color: #182238; }
        header { background: #13213c; color: white; padding: 16px 5%; display: flex;
                 justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
        header a { color: white; text-decoration: none; margin-left: 12px; }
        header form { display: inline; margin-left: 12px; }
        main { width: min(1000px, 92%); margin: 28px auto; }
        .card { background: white; padding: 22px; border-radius: 14px;
                box-shadow: 0 3px 14px #14213d12; margin-bottom: 18px; overflow-wrap: anywhere; }
        .platforms { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
        h1, h2, h3 { margin-top: 0; }
        label { display: block; margin: 12px 0 6px; font-weight: bold; }
        input, select, textarea { width: 100%; padding: 12px; border: 1px solid #ccd3df;
                                  border-radius: 8px; font-size: 16px; font-family: inherit; }
        input[type=checkbox] { width: auto; margin-right: 6px; }
        button, .button { display: inline-block; border: 0; border-radius: 8px; padding: 11px 15px;
                          background: #1769e0; color: white; cursor: pointer;
                          text-decoration: none; font-size: 15px; }
        .secondary { background: #34445f; }
        .muted { color: #64718a; line-height: 1.5; }
        .message { padding: 12px; border-radius: 8px; background: #eaf2ff; margin-bottom: 14px; }
        .message.error { background: #fdeaea; color: #8a1f1f; }
        .ok { color: #087443; font-weight: bold; }
        .bad { color: #b42318; font-weight: bold; }
        .status { font-weight: bold; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
        hr { border: 0; border-top: 1px solid #e3e8f0; margin: 14px 0; }
        footer { text-align: center; color: #64718a; padding: 25px; }
    </style>
</head>
<body>
<header>
    <strong>Social Media Manager</strong>
    <nav>
        {% if session.get('user_id') %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('compose') }}">Compose</a>
            <a href="{{ url_for('schedule') }}">Schedule</a>
            <a href="{{ url_for('history') }}">History</a>
            <a href="{{ url_for('settings') }}">Settings</a>
            <form method="post" action="{{ url_for('logout') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button type="submit" class="secondary">Logout</button>
            </form>
        {% else %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
        {% endif %}
    </nav>
</header>
<main>
    {% for category, message in get_flashed_messages(with_categories=true) %}
        <div class="message {{ category }}">{{ message }}</div>
    {% endfor %}
    {{ content }}
</main>
<footer>Social Media Account Manager - development version</footer>
</body>
</html>
"""


def page(title, template, **context):
    body = render_template_string(template, **context)
    return render_template_string(BASE_TEMPLATE, title=title, content=Markup(body))


# ======================================================================
# HOME / REGISTER / LOGIN / LOGOUT
# ======================================================================

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return page("Home", """
        <section class="card">
            <h1>Manage your social accounts in one place</h1>
            <p class="muted">Send and schedule messages to WhatsApp and Telegram from one dashboard.</p>
            <div class="actions">
                <a class="button" href="{{ url_for('register') }}">Create account</a>
                <a class="button secondary" href="{{ url_for('login') }}">Log in</a>
            </div>
        </section>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill in every field.", "error")
        elif len(username) > 50 or len(email) > 254 or "@" not in email:
            flash("Check your username and email address.", "error")
        elif not 8 <= len(password) <= 256:
            flash("Password must be 8 to 256 characters.", "error")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        (username, email, generate_password_hash(password)),
                    )
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email address is already registered.", "error")

    return page("Register", """
        <section class="card">
            <h1>Create an account</h1>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Username</label>
                <input name="username" maxlength="50" required>
                <label>Email</label>
                <input type="email" name="email" maxlength="254" required>
                <label>Password (at least 8 characters)</label>
                <input type="password" name="password" minlength="8" maxlength="256" required>
                <div class="actions"><button type="submit">Register</button></div>
            </form>
        </section>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ? OR username = ?",
                (identifier.lower(), identifier),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            csrf_token()
            return redirect(url_for("dashboard"))
        flash("Incorrect email/username or password.", "error")

    return page("Login", """
        <section class="card">
            <h1>Log in</h1>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Email or username</label>
                <input name="identifier" required>
                <label>Password</label>
                <input type="password" name="password" required>
                <div class="actions"><button type="submit">Log in</button></div>
            </form>
        </section>
    """)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


# ======================================================================
# DASHBOARD
# ======================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        for platform in PLATFORMS:
            db.execute(
                """INSERT OR IGNORE INTO social_accounts
                   (user_id, platform, account_name, status)
                   VALUES (?, ?, '', 'Not connected')""",
                (session["user_id"], platform),
            )
        accounts = db.execute(
            """SELECT platform, account_name, status FROM social_accounts
               WHERE user_id = ? ORDER BY platform""",
            (session["user_id"],),
        ).fetchall()

    return page("Dashboard", """
        <section class="card">
            <h1>Welcome, {{ session.get('username', 'User') }}!</h1>
            <p class="muted">Manage your account integrations below.</p>
            <div class="actions">
                <a class="button" href="{{ url_for('compose') }}">Compose message</a>
                <a class="button secondary" href="{{ url_for('schedule') }}">Schedule message</a>
                <a class="button secondary" href="{{ url_for('history') }}">History</a>
            </div>
        </section>

        <section class="platforms">
            {% for a in accounts %}
            <article class="card">
                <h2>{{ a['platform'] }}</h2>
                <p class="status">Status: {{ a['status'] or 'Not connected' }}</p>
                {% if a['account_name'] %}
                    <p class="muted">Account: {{ a['account_name'] }}</p>
                {% endif %}
                <div class="actions">
                {% if a['platform'] == 'WhatsApp' %}
                    <a class="button" href="{{ url_for('whatsapp_status') }}">Check connection</a>
                    <a class="button secondary" href="{{ url_for('whatsapp_send') }}">Send message</a>
                {% elif a['platform'] == 'Telegram' %}
                    <a class="button" href="{{ url_for('telegram') }}">Open Telegram</a>
                {% else %}
                    <a class="button secondary" href="{{ url_for('settings') }}">Account settings</a>
                {% endif %}
                </div>
            </article>
            {% endfor %}
        </section>
    """, accounts=accounts)


# ======================================================================
# WHATSAPP
# ======================================================================

@app.route("/whatsapp/status")
@login_required
def whatsapp_status():
    ok, details, display_phone, verified_name = wa_check()
    status = "Connected" if ok else "Connection failed"
    set_status("WhatsApp", status, display_phone or verified_name)

    return page("WhatsApp Status", """
        <section class="card">
            <h1>WhatsApp Cloud API</h1>
            <p class="status">Status: {{ status }}</p>
            <p>{{ details }}</p>
            {% if display_phone %}<p><strong>Business phone:</strong> {{ display_phone }}</p>{% endif %}
            {% if verified_name %}<p><strong>Verified name:</strong> {{ verified_name }}</p>{% endif %}
            <div class="actions">
                <a class="button" href="{{ url_for('whatsapp_status') }}">Check again</a>
                <a class="button secondary" href="{{ url_for('dashboard') }}">Back</a>
            </div>
        </section>
    """, status=status, details=details,
        display_phone=display_phone, verified_name=verified_name)


@app.route("/whatsapp/send", methods=["GET", "POST"])
@login_required
def whatsapp_send():
    result = None
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()
        message = request.form.get("message", "").strip()
        if not recipient or not message:
            result = (False, "Enter both the recipient number and the message.")
        elif len(message) > 4000:
            result = (False, "Message is too long (max 4000 characters).")
        else:
            result = wa_send(recipient, message)
            log_message("WhatsApp", recipient, message, result[0], result[1], "Direct")

    return page("Send WhatsApp", """
        <section class="card">
            <h1>Send WhatsApp message</h1>
            <p class="muted">
                With a Meta test number, the recipient must be on your allowed list, and
                free-text messages only deliver if they messaged you in the last 24 hours.
            </p>
            {% if result %}
                <p class="{{ 'ok' if result[0] else 'bad' }}">
                    {{ 'Sent' if result[0] else 'Failed' }}: {{ result[1] }}
                </p>
            {% endif %}
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Recipient number (country code, digits only)</label>
                <input name="recipient" placeholder="2547XXXXXXXX" required>
                <label>Message</label>
                <textarea name="message" rows="4" maxlength="4000" required></textarea>
                <div class="actions"><button type="submit">Send</button></div>
            </form>
        </section>
    """, result=result)


# ======================================================================
# TELEGRAM
# ======================================================================

@app.route("/telegram", methods=["GET", "POST"])
@login_required
def telegram():
    result = None
    selected = request.args.get("chat", "").strip()

    if request.method == "POST":
        chat_id = request.form.get("chat_id", "").strip()
        message = request.form.get("message", "").strip()
        if not chat_id or not message:
            result = (False, "Enter both the chat ID and the message.")
        elif len(message) > 4000:
            result = (False, "Message is too long (max 4000 characters).")
        else:
            ok, info = tg_call("sendMessage", {"chat_id": chat_id, "text": message})
            result = (ok, "Message sent." if ok else str(info))
            log_message("Telegram", chat_id, message, ok, result[1], "Direct")
        selected = chat_id

    ok, bot = tg_call("getMe")
    bot_name = (bot or {}).get("username", "") if ok and isinstance(bot, dict) else ""
    set_status("Telegram", "Connected" if ok else "Connection failed", bot_name)
    bot_error = "" if ok else str(bot)
    chats = tg_recent_chats() if ok else {}

    return page("Telegram", """
        <section class="card">
            <h1>Telegram bot</h1>
            {% if bot_name %}
                <p class="ok">Connected as @{{ bot_name }}</p>
            {% else %}
                <p class="bad">Not connected: {{ bot_error }}</p>
            {% endif %}
            <p class="muted">A chat appears below after that person sends your bot a message.</p>
        </section>

        {% if chats %}
        <section class="card">
            <h2>Recent chats</h2>
            {% for cid, name in chats.items() %}
                <p><a href="{{ url_for('telegram', chat=cid) }}">{{ name }}</a> ({{ cid }})</p>
            {% endfor %}
        </section>
        {% endif %}

        <section class="card">
            <h2>Send message</h2>
            {% if result %}
                <p class="{{ 'ok' if result[0] else 'bad' }}">{{ 'Sent' if result[0] else 'Failed' }}: {{ result[1] }}</p>
            {% endif %}
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Chat ID</label>
                <input name="chat_id" value="{{ selected }}" required>
                <label>Message</label>
                <textarea name="message" rows="4" maxlength="4000" required></textarea>
                <div class="actions"><button type="submit">Send</button></div>
            </form>
        </section>
    """, result=result, bot_name=bot_name, bot_error=bot_error, chats=chats, selected=selected)


# ======================================================================
# COMPOSE (send to several platforms at once)
# ======================================================================

@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    results = []

    if request.method == "POST":
        message = request.form.get("message", "").strip()
        use_wa = request.form.get("send_whatsapp") == "on"
        use_tg = request.form.get("send_telegram") == "on"
        wa_to = request.form.get("wa_recipient", "").strip()
        tg_chat = request.form.get("tg_chat", "").strip()

        if not message:
            flash("Write a message first.", "error")
        elif len(message) > 4000:
            flash("Message is too long (max 4000 characters).", "error")
        elif not (use_wa or use_tg):
            flash("Select at least one platform.", "error")
        else:
            if use_wa:
                if not wa_to:
                    results.append(("WhatsApp", False, "Enter a recipient number."))
                else:
                    ok, detail = wa_send(wa_to, message)
                    results.append(("WhatsApp", ok, detail))
                    log_message("WhatsApp", wa_to, message, ok, detail, "Compose")
            if use_tg:
                if not tg_chat:
                    results.append(("Telegram", False, "Enter a chat ID."))
                else:
                    ok, info = tg_call("sendMessage", {"chat_id": tg_chat, "text": message})
                    detail = "Message sent." if ok else str(info)
                    results.append(("Telegram", ok, detail))
                    log_message("Telegram", tg_chat, message, ok, detail, "Compose")

    return page("Compose", """
        <section class="card">
            <h1>Compose message</h1>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

                <label>Message</label>
                <textarea name="message" rows="5" maxlength="4000" required></textarea>

                <label><input type="checkbox" name="send_whatsapp"> WhatsApp</label>
                <input name="wa_recipient" placeholder="Recipient number, e.g. 2547XXXXXXXX">

                <label><input type="checkbox" name="send_telegram"> Telegram</label>
                <input name="tg_chat" placeholder="Telegram chat ID">

                <div class="actions"><button type="submit">Send</button></div>
            </form>
        </section>

        {% if results %}
        <section class="card">
            <h2>Results</h2>
            {% for name, ok, detail in results %}
                <p><strong>{{ name }}:</strong>
                   <span class="{{ 'ok' if ok else 'bad' }}">{{ 'Sent' if ok else 'Failed' }}</span>
                   - {{ detail }}</p>
            {% endfor %}
        </section>
        {% endif %}
    """, results=results)


# ======================================================================
# SCHEDULED MESSAGES
# ======================================================================

def send_due_messages():
    now = datetime.now().strftime("%Y-%m-%dT%H:%M")
    with get_db() as db:
        due = db.execute(
            "SELECT * FROM scheduled_messages WHERE status = 'Pending' AND send_at <= ?",
            (now,),
        ).fetchall()

    for row in due:
        # Claim the row first so it can never be sent twice.
        with get_db() as db:
            claimed = db.execute(
                "UPDATE scheduled_messages SET status = 'Sending' WHERE id = ? AND status = 'Pending'",
                (row["id"],),
            ).rowcount
        if not claimed:
            continue

        if row["platform"] == "WhatsApp":
            ok, detail = wa_send(row["target"], row["message"])
        else:
            ok, info = tg_call("sendMessage", {"chat_id": row["target"], "text": row["message"]})
            detail = "Message sent." if ok else str(info)

        log_message(row["platform"], row["target"], row["message"],
                    ok, detail, "Scheduled", user_id=row["user_id"])

        with get_db() as db:
            db.execute(
                "UPDATE scheduled_messages SET status = ?, detail = ? WHERE id = ?",
                ("Sent" if ok else "Failed", str(detail)[:300], row["id"]),
            )


def scheduler_loop():
    while True:
        try:
            send_due_messages()
        except Exception as exc:
            print("Scheduler error:", type(exc).__name__)
        time.sleep(30)


@app.route("/schedule", methods=["GET", "POST"])
@login_required
def schedule():
    if request.method == "POST":
        platform = request.form.get("platform", "")
        target = request.form.get("target", "").strip()
        message = request.form.get("message", "").strip()
        send_at = request.form.get("send_at", "").strip()

        try:
            when = datetime.strptime(send_at, "%Y-%m-%dT%H:%M")
        except ValueError:
            when = None

        if platform not in ("WhatsApp", "Telegram"):
            flash("Choose WhatsApp or Telegram.", "error")
        elif not target or not message:
            flash("Enter the recipient and the message.", "error")
        elif len(message) > 4000:
            flash("Message is too long (max 4000 characters).", "error")
        elif when is None:
            flash("Choose a valid date and time.", "error")
        elif when <= datetime.now():
            flash("Choose a time in the future.", "error")
        else:
            with get_db() as db:
                db.execute(
                    """INSERT INTO scheduled_messages
                       (user_id, platform, target, message, send_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (session["user_id"], platform, target, message, send_at),
                )
            flash("Message scheduled.", "success")
            return redirect(url_for("schedule"))

    with get_db() as db:
        items = db.execute(
            """SELECT * FROM scheduled_messages WHERE user_id = ?
               ORDER BY send_at DESC LIMIT 50""",
            (session["user_id"],),
        ).fetchall()

    return page("Schedule", """
        <section class="card">
            <h1>Schedule a message</h1>
            <p class="muted">Messages send only while this app is running on your computer.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Platform</label>
                <select name="platform" required>
                    <option>Telegram</option>
                    <option>WhatsApp</option>
                </select>
                <label>Recipient (Telegram chat ID, or WhatsApp number like 2547XXXXXXXX)</label>
                <input name="target" required>
                <label>Message</label>
                <textarea name="message" rows="4" maxlength="4000" required></textarea>
                <label>Send at</label>
                <input type="datetime-local" name="send_at" required>
                <div class="actions"><button type="submit">Schedule</button></div>
            </form>
        </section>

        <section class="card">
            <h2>Your scheduled messages</h2>
            {% for m in items %}
                <p>
                    <strong>{{ m['send_at'].replace('T', ' ') }}</strong> -
                    {{ m['platform'] }} to {{ m['target'] }} -
                    <span class="{{ 'ok' if m['status'] == 'Sent' else ('bad' if m['status'] == 'Failed' else '') }}">{{ m['status'] }}</span>
                    {% if m['detail'] %}({{ m['detail'] }}){% endif %}<br>
                    <span class="muted">{{ m['message'][:120] }}</span>
                </p>
                {% if m['status'] == 'Pending' %}
                <form method="post" action="{{ url_for('cancel_scheduled', msg_id=m['id']) }}">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <button type="submit" class="secondary">Cancel</button>
                </form>
                {% endif %}
                <hr>
            {% else %}
                <p>Nothing scheduled yet.</p>
            {% endfor %}
        </section>
    """, items=items)


@app.route("/schedule/<int:msg_id>/cancel", methods=["POST"])
@login_required
def cancel_scheduled(msg_id):
    with get_db() as db:
        db.execute(
            "DELETE FROM scheduled_messages WHERE id = ? AND user_id = ? AND status = 'Pending'",
            (msg_id, session["user_id"]),
        )
    flash("Scheduled message cancelled.", "success")
    return redirect(url_for("schedule"))


# ======================================================================
# MESSAGE HISTORY
# ======================================================================

@app.route("/history")
@login_required
def history():
    with get_db() as db:
        rows = db.execute(
            """SELECT * FROM message_log WHERE user_id = ?
               ORDER BY id DESC LIMIT 100""",
            (session["user_id"],),
        ).fetchall()

    return page("History", """
        <section class="card">
            <h1>Message history</h1>
            <p class="muted">The last 100 messages sent from this app.</p>
            {% for r in rows %}
                <p>
                    <strong>{{ r['created_at'] }}</strong> -
                    {{ r['platform'] }} to {{ r['target'] }}
                    ({{ r['source'] }}) -
                    <span class="{{ 'ok' if r['ok'] else 'bad' }}">{{ 'Sent' if r['ok'] else 'Failed' }}</span><br>
                    <span class="muted">{{ r['message'][:150] }}</span>
                    {% if not r['ok'] and r['detail'] %}<br><span class="bad">{{ r['detail'] }}</span>{% endif %}
                </p>
                <hr>
            {% else %}
                <p>No messages sent yet.</p>
            {% endfor %}
        </section>
    """, rows=rows)


# ======================================================================
# SETTINGS (account labels only - never store passwords or tokens here)
# ======================================================================

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        platform = request.form.get("platform", "")
        account_name = request.form.get("account_name", "").strip()

        if platform not in PLATFORMS:
            flash("Please select a supported platform.", "error")
        elif len(account_name) > 120:
            flash("Label is too long.", "error")
        else:
            with get_db() as db:
                db.execute(
                    """INSERT OR IGNORE INTO social_accounts
                       (user_id, platform, account_name, status)
                       VALUES (?, ?, '', 'Not connected')""",
                    (session["user_id"], platform),
                )
                db.execute(
                    """UPDATE social_accounts SET account_name = ?
                       WHERE user_id = ? AND platform = ?""",
                    (account_name, session["user_id"], platform),
                )
            flash("Label saved. This does not authorize a platform connection.", "success")
            return redirect(url_for("settings"))

    with get_db() as db:
        accounts = db.execute(
            """SELECT platform, account_name, status FROM social_accounts
               WHERE user_id = ? ORDER BY platform""",
            (session["user_id"],),
        ).fetchall()

    return page("Settings", """
        <section class="card">
            <h1>Account settings</h1>
            <p class="muted">Save a label for each account. Never enter passwords or API tokens here.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label>Platform</label>
                <select name="platform" required>
                    {% for p in platforms %}<option value="{{ p }}">{{ p }}</option>{% endfor %}
                </select>
                <label>Account label</label>
                <input name="account_name" maxlength="120" placeholder="e.g. My business account">
                <div class="actions"><button type="submit">Save label</button></div>
            </form>
        </section>
        <section class="card">
            <h2>Saved accounts</h2>
            {% for a in accounts %}
                <p><strong>{{ a['platform'] }}:</strong>
                   {{ a['account_name'] or 'No label saved' }} - {{ a['status'] or 'Not connected' }}</p>
            {% else %}
                <p>No saved accounts.</p>
            {% endfor %}
        </section>
    """, platforms=PLATFORMS, accounts=accounts)


# ======================================================================
# ERROR PAGES
# ======================================================================

@app.errorhandler(400)
def bad_request(error):
    return page("Request Error", """
        <section class="card">
            <h1>Request could not be processed</h1>
            <p>{{ message }}</p>
            <a class="button" href="{{ url_for('home') }}">Home</a>
        </section>
    """, message=getattr(error, "description", "Invalid request.")), 400


@app.errorhandler(404)
def not_found(error):
    return page("Not Found", """
        <section class="card">
            <h1>Page not found</h1>
            <a class="button" href="{{ url_for('home') }}">Home</a>
        </section>
    """), 404


if __name__ == "__main__":
    # Local development only. The scheduler thread sends due messages every 30 seconds.
    threading.Thread(target=scheduler_loop, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False)