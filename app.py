from dotenv import load_dotenv

load_dotenv()

import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template_string,
    request, session, url_for,
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from telegram_helper import get_bot_info, recent_chats, send_message as tg_send
from whatsapp_sender import send_whatsapp_message

# ---------------------------------------------------------------- setup

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "users.db"))
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "local-dev-only-change-before-deploy"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

PLATFORMS = ["Facebook", "WhatsApp", "Instagram", "TikTok", "Telegram"]
SENDABLE = ["WhatsApp", "Telegram"]
EAT = timezone(timedelta(hours=3))  # Africa/Nairobi


# ------------------------------------------------------------- database

def get_db():
    db = sqlite3.connect(str(DATABASE), timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS social_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            account_name TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Not connected',
            UNIQUE(user_id, platform),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)""")
        db.execute("""CREATE TABLE IF NOT EXISTS message_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            target TEXT NOT NULL,
            message TEXT NOT NULL,
            success INTEGER NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL DEFAULT 'Direct',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)""")
        db.execute("""CREATE TABLE IF NOT EXISTS scheduled_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            target TEXT NOT NULL,
            message TEXT NOT NULL,
            send_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)""")


def now_utc():
    return datetime.now(timezone.utc)


def to_eat_text(utc_iso):
    try:
        return datetime.fromisoformat(utc_iso).astimezone(EAT).strftime("%d %b %Y %H:%M")
    except ValueError:
        return utc_iso


def log_message(user_id, platform, target, message, ok, detail, kind):
    with get_db() as db:
        db.execute(
            """INSERT INTO message_log
               (user_id, platform, target, message, success, detail, kind, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, platform, target, message, 1 if ok else 0,
             detail, kind, now_utc().isoformat()),
        )


def dispatch(platform, target, message):
    if platform == "WhatsApp":
        return send_whatsapp_message(target, message)
    if platform == "Telegram":
        return tg_send(target, message)
    return False, "Unsupported platform."


# -------------------------------------------------------------- scheduler

_scheduler_lock = threading.Lock()


def run_due_messages():
    with _scheduler_lock:
        with get_db() as db:
            due = db.execute(
                """SELECT * FROM scheduled_messages
                   WHERE status = 'Pending' AND send_at <= ?""",
                (now_utc().isoformat(),),
            ).fetchall()
            for row in due:
                # Claim the row first so it can never be sent twice.
                claimed = db.execute(
                    "UPDATE scheduled_messages SET status = 'Sending' "
                    "WHERE id = ? AND status = 'Pending'", (row["id"],)
                ).rowcount
                if not claimed:
                    continue
                db.commit()
                ok, detail = dispatch(row["platform"], row["target"], row["message"])
                db.execute(
                    "UPDATE scheduled_messages SET status = ? WHERE id = ?",
                    ("Sent" if ok else "Failed", row["id"]),
                )
                db.commit()
                log_message(row["user_id"], row["platform"], row["target"],
                            row["message"], ok, detail, "Scheduled")


def scheduler_loop():
    while True:
        try:
            run_due_messages()
        except Exception as exc:  # keep the thread alive
            print("Scheduler error:", type(exc).__name__)
        time.sleep(30)


_started = False


def start_scheduler():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=scheduler_loop, daemon=True).start()


# --------------------------------------------------------------- security

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_post():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        saved = session.get("csrf_token", "")
        if not sent or not saved or not hmac.compare_digest(sent, saved):
            abort(400, description="Your form expired. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# ----------------------------------------------------------------- layout

LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | Social Media Manager</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, sans-serif; background: #f3f6fb; color: #182238; }
header { background: #13213c; color: #fff; padding: 16px 5%; display: flex;
         justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
header a { color: #fff; text-decoration: none; margin-left: 14px; }
header form { display: inline; margin-left: 14px; }
header form button { padding: 6px 12px; }
main { width: min(1000px, 92%); margin: 28px auto; }
.card { background: #fff; padding: 22px; border-radius: 14px; margin-bottom: 18px;
        box-shadow: 0 3px 14px #14213d12; overflow-wrap: anywhere; }
.platforms { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
h1, h2, h3 { margin-top: 0; }
label { display: block; margin: 12px 0 6px; font-weight: bold; }
input, select, textarea { width: 100%; padding: 12px; border: 1px solid #ccd3df;
        border-radius: 8px; font-size: 16px; font-family: inherit; }
textarea { min-height: 120px; }
button, .button { display: inline-block; border: 0; border-radius: 8px; padding: 11px 15px;
        background: #1769e0; color: #fff; cursor: pointer; text-decoration: none; font-size: 15px; }
.secondary { background: #34445f; }
.danger { background: #a72b35; }
.muted { color: #64718a; line-height: 1.5; }
.message { padding: 12px; border-radius: 8px; background: #eaf2ff; margin-bottom: 14px; }
.message.error { background: #fdeaea; color: #8a1f1f; }
.message.success { background: #e6f6ec; color: #17673a; }
.status { font-weight: bold; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e3e8f0; vertical-align: top; }
.ok { color: #17673a; font-weight: bold; }
.bad { color: #a72b35; font-weight: bold; }
.scroll { overflow-x: auto; }
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
{% for category, text in get_flashed_messages(with_categories=true) %}
  <div class="message {{ category }}">{{ text }}</div>
{% endfor %}
{{ content }}
</main>
<footer>Social Media Manager</footer>
</body>
</html>
"""


def page(title, template, code=200, **context):
    body = render_template_string(template, **context)
    html = render_template_string(LAYOUT, title=title, content=Markup(body))
    return html, code


# ------------------------------------------------------------------ auth

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return page("Home", """
    <section class="card">
      <h1>Manage your social accounts in one place</h1>
      <p class="muted">Send and schedule WhatsApp and Telegram messages from one dashboard.</p>
      <div class="actions">
        <a class="button" href="{{ url_for('register') }}">Create account</a>
        <a class="button secondary" href="{{ url_for('login') }}">Log in</a>
      </div>
    </section>""")


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
                flash("That email is already registered.", "error")

    return page("Register", """
    <section class="card">
      <h1>Create an account</h1>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Username</label><input name="username" maxlength="50" required>
        <label>Email</label><input type="email" name="email" maxlength="254" required>
        <label>Password (at least 8 characters)</label>
        <input type="password" name="password" minlength="8" maxlength="256" required>
        <div class="actions"><button type="submit">Register</button></div>
      </form>
    </section>""")


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
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        flash("Incorrect email/username or password.", "error")

    return page("Login", """
    <section class="card">
      <h1>Log in</h1>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Email or username</label><input name="identifier" required>
        <label>Password</label><input type="password" name="password" required>
        <div class="actions"><button type="submit">Log in</button></div>
      </form>
    </section>""")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


# ------------------------------------------------------------- dashboard

def ensure_platform_rows(user_id):
    with get_db() as db:
        for platform in PLATFORMS:
            db.execute(
                """INSERT OR IGNORE INTO social_accounts
                   (user_id, platform, account_name, status)
                   VALUES (?, ?, '', 'Not connected')""",
                (user_id, platform),
            )


@app.route("/dashboard")
@login_required
def dashboard():
    ensure_platform_rows(session["user_id"])
    with get_db() as db:
        accounts = db.execute(
            "SELECT platform, account_name, status FROM social_accounts "
            "WHERE user_id = ? ORDER BY platform", (session["user_id"],)
        ).fetchall()

    return page("Dashboard", """
    <section class="card">
      <h1>Welcome, {{ session.get('username', 'User') }}!</h1>
      <p class="muted">Manage your platform integrations below.</p>
    </section>
    <section class="platforms">
    {% for a in accounts %}
      <article class="card">
        <h2>{{ a['platform'] }}</h2>
        <p class="status">Status: {{ a['status'] or 'Not connected' }}</p>
        {% if a['account_name'] %}<p class="muted">Account: {{ a['account_name'] }}</p>{% endif %}
        <div class="actions">
        {% if a['platform'] == 'WhatsApp' %}
          <a class="button" href="{{ url_for('whatsapp_status') }}">Check connection</a>
          <a class="button secondary" href="{{ url_for('compose') }}">Send</a>
        {% elif a['platform'] == 'Telegram' %}
          <a class="button" href="{{ url_for('telegram') }}">Open Telegram</a>
          <a class="button secondary" href="{{ url_for('compose') }}">Send</a>
        {% else %}
          <a class="button secondary" href="{{ url_for('settings') }}">Account settings</a>
        {% endif %}
        </div>
        {% if a['platform'] in ('Facebook', 'Instagram', 'TikTok') %}
          <p class="muted">Official authorization is not configured yet.</p>
        {% endif %}
      </article>
    {% endfor %}
    </section>""", accounts=accounts)


# -------------------------------------------------------------- WhatsApp

def set_status(platform, status, account_name=None):
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO social_accounts
               (user_id, platform, account_name, status) VALUES (?, ?, '', 'Not connected')""",
            (session["user_id"], platform),
        )
        if account_name is None:
            db.execute(
                "UPDATE social_accounts SET status = ? WHERE user_id = ? AND platform = ?",
                (status, session["user_id"], platform),
            )
        else:
            db.execute(
                "UPDATE social_accounts SET status = ?, account_name = ? "
                "WHERE user_id = ? AND platform = ?",
                (status, account_name, session["user_id"], platform),
            )


@app.route("/whatsapp/status")
@login_required
def whatsapp_status():
    import requests

    token = os.environ.get("WA_ACCESS_TOKEN", "").strip()
    phone_id = os.environ.get("WA_PHONE_NUMBER_ID", "").strip()
    version = os.environ.get("WA_API_VERSION", "v22.0").strip() or "v22.0"
    status, details, phone, name = "Not configured", "", "", ""

    if not token or not phone_id:
        details = "WA_ACCESS_TOKEN or WA_PHONE_NUMBER_ID is missing from the server environment."
    else:
        try:
            r = requests.get(
                f"https://graph.facebook.com/{version}/{phone_id}",
                headers={"Authorization": f"Bearer {token}"},
                params={"fields": "display_phone_number,verified_name"},
                timeout=15,
            )
            data = r.json()
            if r.ok:
                status = "Connected"
                details = "WhatsApp Cloud API access was verified."
                phone = data.get("display_phone_number", "")
                name = data.get("verified_name", "")
            else:
                status = "Connection failed"
                details = (data.get("error") or {}).get("message", "Meta returned an error.")
        except (requests.RequestException, ValueError):
            status = "Connection failed"
            details = "Could not reach Meta."

    set_status("WhatsApp", status, phone or name or "")
    return page("WhatsApp", """
    <section class="card">
      <h1>WhatsApp Cloud API</h1>
      <p class="status">Status: {{ status }}</p>
      <p>{{ details }}</p>
      {% if phone %}<p><strong>Business phone:</strong> {{ phone }}</p>{% endif %}
      {% if name %}<p><strong>Verified name:</strong> {{ name }}</p>{% endif %}
      <div class="actions">
        <a class="button" href="{{ url_for('whatsapp_status') }}">Check again</a>
        <a class="button secondary" href="{{ url_for('dashboard') }}">Back</a>
      </div>
    </section>""", status=status, details=details, phone=phone, name=name)


# -------------------------------------------------------------- Telegram

@app.route("/telegram")
@login_required
def telegram():
    bot_ok, bot = get_bot_info()
    chats_ok, chats = recent_chats() if bot_ok else (False, bot)
    if bot_ok:
        set_status("Telegram", "Connected", "@" + (bot.get("username") or ""))
    else:
        set_status("Telegram", "Connection failed")

    return page("Telegram", """
    <section class="card">
      <h1>Telegram bot</h1>
      {% if bot_ok %}
        <p class="status">Status: Connected</p>
        <p><strong>Bot:</strong> @{{ bot.get('username') }}</p>
        <p class="muted">People must message your bot first. They then appear below.</p>
      {% else %}
        <p class="status">Status: Connection failed</p><p>{{ bot }}</p>
      {% endif %}
    </section>
    {% if bot_ok %}
    <section class="card">
      <h2>Chats that messaged the bot</h2>
      {% if chats_ok and chats %}
        <table><tr><th>Name</th><th>Type</th><th>Chat ID</th></tr>
        {% for c in chats %}<tr><td>{{ c.name }}</td><td>{{ c.type }}</td><td>{{ c.id }}</td></tr>{% endfor %}
        </table>
      {% else %}<p class="muted">No chats yet. Send "hello" to your bot in Telegram.</p>{% endif %}
      <div class="actions"><a class="button" href="{{ url_for('compose') }}">Send a message</a></div>
    </section>
    {% endif %}""", bot_ok=bot_ok, bot=bot, chats_ok=chats_ok, chats=chats if chats_ok else [])


# --------------------------------------------------------------- compose

@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    if request.method == "POST":
        platform = request.form.get("platform", "")
        target = request.form.get("target", "").strip()
        message = request.form.get("message", "").strip()

        if platform not in SENDABLE or not target or not message:
            flash("Choose a platform and fill in the recipient and message.", "error")
        else:
            ok, detail = dispatch(platform, target, message)
            log_message(session["user_id"], platform, target, message, ok, detail, "Direct")
            flash(detail, "success" if ok else "error")
            if ok:
                return redirect(url_for("history"))

    return page("Compose", """
    <section class="card">
      <h1>Send a message</h1>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Platform</label>
        <select name="platform">{% for p in sendable %}<option>{{ p }}</option>{% endfor %}</select>
        <label>Recipient (WhatsApp: number with country code. Telegram: chat ID)</label>
        <input name="target" maxlength="40" required>
        <label>Message</label>
        <textarea name="message" maxlength="4096" required></textarea>
        <div class="actions"><button type="submit">Send now</button></div>
      </form>
      <p class="muted">WhatsApp test numbers can only message recipients added in the Meta dashboard.</p>
    </section>""", sendable=SENDABLE)


# -------------------------------------------------------------- schedule

@app.route("/schedule", methods=["GET", "POST"])
@login_required
def schedule():
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "cancel":
            with get_db() as db:
                db.execute(
                    "UPDATE scheduled_messages SET status = 'Cancelled' "
                    "WHERE id = ? AND user_id = ? AND status = 'Pending'",
                    (request.form.get("id", ""), session["user_id"]),
                )
            flash("Scheduled message cancelled.", "success")
            return redirect(url_for("schedule"))

        platform = request.form.get("platform", "")
        target = request.form.get("target", "").strip()
        message = request.form.get("message", "").strip()
        when = request.form.get("send_at", "")
        try:
            send_at = datetime.fromisoformat(when).replace(tzinfo=EAT).astimezone(timezone.utc)
        except ValueError:
            send_at = None

        if platform not in SENDABLE or not target or not message or send_at is None:
            flash("Fill in every field with a valid date and time.", "error")
        elif send_at <= now_utc():
            flash("Pick a time in the future (Nairobi time).", "error")
        else:
            with get_db() as db:
                db.execute(
                    """INSERT INTO scheduled_messages
                       (user_id, platform, target, message, send_at) VALUES (?, ?, ?, ?, ?)""",
                    (session["user_id"], platform, target, message, send_at.isoformat()),
                )
            flash("Message scheduled.", "success")
            return redirect(url_for("schedule"))

    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM scheduled_messages WHERE user_id = ? ORDER BY send_at DESC LIMIT 50",
            (session["user_id"],),
        ).fetchall()
    items = [dict(r, when=to_eat_text(r["send_at"])) for r in rows]

    return page("Schedule", """
    <section class="card">
      <h1>Schedule a message</h1>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Platform</label>
        <select name="platform">{% for p in sendable %}<option>{{ p }}</option>{% endfor %}</select>
        <label>Recipient</label><input name="target" maxlength="40" required>
        <label>Message</label><textarea name="message" maxlength="4096" required></textarea>
        <label>Send at (Nairobi time)</label>
        <input type="datetime-local" name="send_at" required>
        <div class="actions"><button type="submit">Schedule</button></div>
      </form>
    </section>
    <section class="card">
      <h2>Your scheduled messages</h2>
      {% if items %}<div class="scroll"><table>
        <tr><th>When</th><th>Platform</th><th>To</th><th>Message</th><th>Status</th><th></th></tr>
        {% for i in items %}<tr>
          <td>{{ i.when }}</td><td>{{ i.platform }}</td><td>{{ i.target }}</td>
          <td>{{ i.message[:60] }}</td><td>{{ i.status }}</td>
          <td>{% if i.status == 'Pending' %}
            <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="cancel">
            <input type="hidden" name="id" value="{{ i.id }}">
            <button class="danger" type="submit">Cancel</button></form>{% endif %}</td>
        </tr>{% endfor %}</table></div>
      {% else %}<p class="muted">Nothing scheduled.</p>{% endif %}
    </section>""", sendable=SENDABLE, items=items)


# --------------------------------------------------------------- history

@app.route("/history")
@login_required
def history():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM message_log WHERE user_id = ? ORDER BY id DESC LIMIT 100",
            (session["user_id"],),
        ).fetchall()
    items = [dict(r, when=to_eat_text(r["created_at"])) for r in rows]

    return page("History", """
    <section class="card">
      <h1>Message history</h1>
      {% if items %}<div class="scroll"><table>
        <tr><th>When</th><th>Platform</th><th>To</th><th>Type</th><th>Result</th><th>Message</th></tr>
        {% for i in items %}<tr>
          <td>{{ i.when }}</td><td>{{ i.platform }}</td><td>{{ i.target }}</td><td>{{ i.kind }}</td>
          <td class="{{ 'ok' if i.success else 'bad' }}">{{ 'Sent' if i.success else 'Failed' }}
            <div class="muted">{{ i.detail }}</div></td>
          <td>{{ i.message[:80] }}</td>
        </tr>{% endfor %}</table></div>
      {% else %}<p class="muted">No messages yet.</p>{% endif %}
    </section>""", items=items)


# -------------------------------------------------------------- settings

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        platform = request.form.get("platform", "")
        label = request.form.get("account_name", "").strip()
        if platform not in PLATFORMS or len(label) > 100:
            flash("Choose a valid platform and a label under 100 characters.", "error")
        else:
            set_status(platform, _current_status(platform), label)
            flash("Label saved. This does not authorize a platform connection.", "success")
            return redirect(url_for("settings"))

    ensure_platform_rows(session["user_id"])
    with get_db() as db:
        accounts = db.execute(
            "SELECT platform, account_name, status FROM social_accounts "
            "WHERE user_id = ? ORDER BY platform", (session["user_id"],)
        ).fetchall()

    return page("Settings", """
    <section class="card">
      <h1>Account labels</h1>
      <p class="muted">Never enter passwords or API tokens here.</p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Platform</label>
        <select name="platform">{% for p in platforms %}<option>{{ p }}</option>{% endfor %}</select>
        <label>Label</label><input name="account_name" maxlength="100">
        <div class="actions"><button type="submit">Save label</button></div>
      </form>
    </section>
    <section class="card">
      <h2>Saved</h2>
      {% for a in accounts %}
        <p><strong>{{ a['platform'] }}:</strong> {{ a['account_name'] or 'No label' }} - {{ a['status'] }}</p>
      {% endfor %}
    </section>""", platforms=PLATFORMS, accounts=accounts)


def _current_status(platform):
    with get_db() as db:
        row = db.execute(
            "SELECT status FROM social_accounts WHERE user_id = ? AND platform = ?",
            (session["user_id"], platform),
        ).fetchone()
    return row["status"] if row else "Not connected"


# ----------------------------------------------------------------- errors

@app.errorhandler(400)
def bad_request(error):
    return page("Request error", """
    <section class="card"><h1>Request could not be processed</h1>
    <p>{{ message }}</p><a class="button" href="{{ url_for('home') }}">Go home</a></section>""",
                code=400, message=getattr(error, "description", "Invalid request."))


@app.errorhandler(404)
def not_found(error):
    return page("Not found", """
    <section class="card"><h1>Page not found</h1>
    <a class="button" href="{{ url_for('home') }}">Go home</a></section>""", code=404)


# ------------------------------------------------------------------ start

init_db()
start_scheduler()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
