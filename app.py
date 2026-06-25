from flask import Flask, request, jsonify
import requests
import base64
import json
import os

app = Flask(__name__)

META_ACCESS_TOKEN = os.environ.get("META_ACCESS_TOKEN")
Valid_Package = "com.DreamVerseGames.PrimalRooms"

def AttestationAuthentication(AttestationToken):
    url = (
        "https://graph.oculus.com/platform_integrity/verify"
        f"?token={AttestationToken}&access_token={META_ACCESS_TOKEN}"
    )

    resp = requests.get(url)
    return resp.json()

def _b64url_safe_decode(s: str) -> bytes:
    s = s.strip()
    padding = (-len(s)) % 4
    s += "=" * padding
    return base64.urlsafe_b64decode(s)

@app.route("/", methods=["GET"])
def home():
    return "Primal Containment Backend is running"

@app.route("/api/authenticate/attestation/mothershipAuth", methods=["POST"])
def MotherShipAuth():
    rjson = request.form

    user_id = rjson.get("UserId")
    attestation_token = rjson.get("AttestationToken")

    if not attestation_token or attestation_token.strip() == "":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED.",
            "BanExpirationTime": "Unknown"
        }), 403

    data = AttestationAuthentication(attestation_token)

    if "data" not in data or len(data["data"]) == 0:
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. Empty Meta response.",
            "BanExpirationTime": "Unknown"
        }), 403

    response_data = data["data"][0]

    if response_data.get("message") != "success":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. Reason: " + str(response_data.get("message")),
            "BanExpirationTime": "Unknown"
        }), 403

    claims = response_data.get("claims")
    decoded_bytes = _b64url_safe_decode(claims)
    claims_json = json.loads(decoded_bytes)

    app_state = claims_json.get("app_state", {})
    device_state = claims_json.get("device_state", {})
    device_ban = claims_json.get("device_ban", {})

    device_integrity_state = device_state.get("device_integrity_state")
    store_recognized = app_state.get("app_integrity_state")
    package_id = app_state.get("package_id")
    sha256_sig = app_state.get("package_cert_sha256_digest")
    device_ban_status = device_ban.get("is_banned", False)

    if package_id != Valid_Package:
        return jsonify({
            "BanMessage": "Invalid package ID.",
            "BanExpirationTime": "Unknown"
        }), 403

    if device_integrity_state != "Advanced":
        return jsonify({
            "BanMessage": "Device integrity failed.",
            "BanExpirationTime": "Unknown"
        }), 403

    if store_recognized != "StoreRecognized":
        return jsonify({
            "BanMessage": "App is not store recognized.",
            "BanExpirationTime": "Unknown"
        }), 403

    if device_ban_status:
        return jsonify({
            "BanMessage": "Device is banned.",
            "BanExpirationTime": "Unknown"
        }), 403

    return jsonify({
        "Success": "OCULUS INTEGRITY AUTHENTICATION PASSED"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
