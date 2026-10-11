import os
import re
import requests


def send_whatsapp_message(recipient, message):
    """Send a text message through the official WhatsApp Cloud API."""
    token = os.environ.get("WA_ACCESS_TOKEN", "").strip()
    phone_number_id = os.environ.get("WA_PHONE_NUMBER_ID", "").strip()
    api_version = os.environ.get("WA_API_VERSION", "v22.0").strip()

    if not token or not phone_number_id:
        return {"success": False,
                "message": "WhatsApp credentials are missing in this session."}

    to = re.sub(r"[\s\-\+\(\)]", "", recipient)
    if not to.isdigit() or not 8 <= len(to) <= 15:
        return {"success": False,
                "message": "Enter the number with country code, digits only (e.g. 2547XXXXXXXX)."}

    if not message or len(message) > 1000:
        return {"success": False,
                "message": "Message must be 1 to 1000 characters."}

    url = f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
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
        return {"success": False, "message": "Could not reach Meta. Try again."}
    except ValueError:
        return {"success": False, "message": "Meta returned an unreadable response."}

    if response.ok:
        return {"success": True, "message": "Message accepted by WhatsApp."}

    error = data.get("error", {}) if isinstance(data, dict) else {}
    return {"success": False,
            "message": error.get("message", f"Meta returned HTTP {response.status_code}.")}