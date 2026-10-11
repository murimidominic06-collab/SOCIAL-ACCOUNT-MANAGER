import os

import requests


def _call(method, payload=None):
    """Call the Telegram Bot API. Returns (ok, data_or_error_text)."""
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    if not token:
        return False, "TG_BOT_TOKEN is not set."

    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        response = requests.post(url, json=payload or {}, timeout=20)
        data = response.json()
    except requests.RequestException:
        return False, "Could not reach Telegram. Check your internet connection."
    except ValueError:
        return False, "Telegram returned an unreadable response."

    if data.get("ok"):
        return True, data.get("result")
    return False, data.get("description", "Telegram returned an error.")


def get_bot_info():
    return _call("getMe")


def fetch_updates(offset=None):
    payload = {"timeout": 0, "limit": 100}
    if offset is not None:
        payload["offset"] = offset
    return _call("getUpdates", payload)


def recent_chats():
    """Return (ok, list of chats that have messaged the bot)."""
    ok, result = fetch_updates()
    if not ok:
        return False, result

    chats = {}
    for update in result:
        message = update.get("message") or update.get("channel_post") or {}
        chat = message.get("chat")
        if not chat:
            continue
        name = (
            chat.get("title")
            or " ".join(
                part for part in (chat.get("first_name"), chat.get("last_name")) if part
            )
            or chat.get("username")
            or str(chat["id"])
        )
        chats[chat["id"]] = {"id": chat["id"], "name": name, "type": chat.get("type", "")}
    return True, list(chats.values())


def send_message(chat_id, text):
    """Returns (ok, detail)."""
    if not str(chat_id).lstrip("-").isdigit():
        return False, "Chat ID must be a number."
    if not text or len(text) > 4096:
        return False, "Message must be between 1 and 4096 characters."

    ok, result = _call("sendMessage", {"chat_id": chat_id, "text": text})
    if ok:
        return True, "Message sent on Telegram."
    return False, result
