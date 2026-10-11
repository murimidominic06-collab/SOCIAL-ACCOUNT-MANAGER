import os
import re

import requests


def send_whatsapp_message(recipient, message):
    """Send a text message through the WhatsApp Cloud API.

    Returns (ok, detail).
    """
    token = os.environ.get("WA_ACCESS_TOKEN", "").strip()
    phone_id = os.environ.get("WA_PHONE_NUMBER_ID", "").strip()
    version = os.environ.get("WA_API_VERSION", "v22.0").strip() or "v22.0"

    if not token or not phone_id:
        return False, "WA_ACCESS_TOKEN or WA_PHONE_NUMBER_ID is not set."

    number = re.sub(r"\D", "", recipient or "")
    if not 8 <= len(number) <= 15:
        return False, "Enter the number with country code, e.g. 254712345678."

    if not message or len(message) > 4096:
        return False, "Message must be between 1 and 4096 characters."

    url = f"https://graph.facebook.com/{version}/{phone_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": number,
        "type": "text",
        "text": {"body": message},
    }

    try:
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=20,
        )
        data = response.json()
    except requests.RequestException:
        return False, "Could not reach Meta. Check your internet connection."
    except ValueError:
        return False, "Meta returned an unreadable response."

    if response.ok:
        return True, "Message accepted by WhatsApp."

    error = data.get("error", {}) if isinstance(data, dict) else {}
    return False, error.get("message", f"Meta returned HTTP {response.status_code}.")
