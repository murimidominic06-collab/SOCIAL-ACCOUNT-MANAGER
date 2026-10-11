import os
import re
import requests

API = "https://api.telegram.org"


def _call(method, payload=None):
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    if not token:
        return None, "Telegram bot token is missing in this session."
    try:
        response = requests.post(
            f"{API}/bot{token}/{method}", json=payload or {}, timeout=20
        )
        data = response.json()
    except requests.RequestException:
        return None, "Could not reach Telegram."
    except ValueError:
        return None, "Telegram returned an unreadable response."
    if isinstance(data, dict) and data.get("ok"):
        return data.get("result"), ""
    description = data.get("description") if isinstance(data, dict) else None
    return None, description or "Telegram returned an error."


def get_bot_info():
    result, error = _call("getMe")
    if result is None:
        return {"success": False, "message": error}
    return {"success": True,
            "name": result.get("first_name", ""),
            "username": result.get("username", "")}


def recent_chats():
    result, _ = _call("getUpdates", {"limit": 50})
    chats = {}
    for update in result or []:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            continue
        name = (chat.get("title")
                or " ".join(filter(None, [chat.get("first_name"),
                                          chat.get("last_name")]))
                or chat.get("username") or "Unknown")
        chats[chat_id] = name
    return [{"id": cid, "name": name} for cid, name in chats.items()]


def send_message(chat_id, text):
    if not re.fullmatch(r"-?\d{1,20}", chat_id or ""):
        return {"success": False, "message": "Chat ID must be a number."}
    if not text or len(text) > 4096:
        return {"success": False,
                "message": "Message must be 1 to 4096 characters."}
    result, error = _call("sendMessage", {"chat_id": chat_id, "text": text})
    if result is None:
        return {"success": False, "message": error}
    return {"success": True, "message": "Message sent."}


def fetch_updates(offset=None):
    """Fetch new incoming text messages. Returns (messages, error)."""
    payload = {"limit": 100, "timeout": 0, "allowed_updates": ["message"]}
    if offset is not None:
        payload["offset"] = offset
    result, error = _call("getUpdates", payload)
    if result is None:
        return [], error

    messages = []
    for update in result:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        if chat.get("id") is None or update.get("update_id") is None:
            continue
        name = (" ".join(filter(None, [sender.get("first_name"),
                                       sender.get("last_name")]))
                or sender.get("username") or chat.get("title") or "Unknown")
        messages.append({
            "update_id": update["update_id"],
            "chat_id": str(chat["id"]),
            "sender": name,
            "text": message.get("text") or "[non-text message]",
            "date": message.get("date") or 0,
        })
    return messages, ""
