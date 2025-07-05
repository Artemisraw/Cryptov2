import os
import time
import base64
import threading
import vonage
from vonage import Auth, Vonage
from vonage_sms import SmsMessage, SmsResponse
from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.urandom(16)

# -------------------------------------------------------------------
# Configuration in the .env file
# -------------------------------------------------------------------
load_dotenv()

NUMBER = os.getenv("number")
API_KEY = os.getenv("key")
API_SECRET = os.getenv("secret")

# Initialize vonage
client = Vonage(Auth(api_key=API_KEY, api_secret=API_SECRET))
sms = client.sms
sms_otp_store = {}

def _sms_otp_queue_cleaner():
    while True:
        now = time.time()
        to_delete = [p for p, (_, exp) in sms_otp_store.items() if exp < now]
        for p in to_delete:
            del sms_otp_store[p]
        time.sleep(60)

threading.Thread(target=_sms_otp_queue_cleaner, daemon=True).start()

# -------------------------------------------------------------------
# SMS helper
# -------------------------------------------------------------------
def send_sms_otp_code(phone_number: str, otp_code: str) -> None:
    message = SmsMessage(
        to=phone_number,
        from_=NUMBER,
        text=f'Your secure OTP is {otp_code}'
    )
    response: SmsResponse = client.sms.send(message)
    print(response)
# -------------------------------------------------------------------
# OTP Generation & Verification
# -------------------------------------------------------------------
def generate_sms_otp(phone: str, valid_minutes: int = 5) -> None:
    """Generate a random 6-digit code, store it with an expiry, and SMS it."""
    otp = f"{int.from_bytes(os.urandom(3), 'big') % 1000000:06d}"
    expires_at = time.time() + valid_minutes * 60
    sms_otp_store[phone] = (otp, expires_at)
    send_sms_otp_code(phone, otp)

def verify_sms_otp(phone: str, otp_code: str) -> bool:
    """Return True if otp_code matches the stored one and isn't expired."""
    entry = sms_otp_store.get(phone)
    used = 0
    if not entry:
        return False
    stored_otp, expires_at = entry
    if time.time() > expires_at:
        del sms_otp_store[phone]
        return False
    if stored_otp == otp_code:
        while(used >= 1):
            del sms_otp_store[phone]  # one-time use
        used = used + 1
        return True
    return False

# -------------------------------------------------------------------
# Key Derivation & Fernet Encryption
# -------------------------------------------------------------------
def derive_fernet_key(pin: str, otp: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from PIN + OTP + salt."""
    passphrase = (pin + otp).encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = kdf.derive(passphrase)
    return base64.urlsafe_b64encode(key)

def encrypt_message(plaintext: str, pin: str, otp: str, phone: str) -> str:
    """Encrypt message using SMS OTP verification."""
    if not verify_sms_otp(phone, otp):
        raise ValueError("Invalid or expired SMS OTP.")

    salt = os.urandom(16)
    fernet_key = derive_fernet_key(pin, otp, salt)
    
    f = Fernet(fernet_key)
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = f.encrypt(plaintext_bytes)

    blob = salt + ciphertext
    return base64.b64encode(blob).decode("utf-8")

def decrypt_message(blob_b64: str, pin: str, otp: str, phone: str) -> str:
    """Decrypt a message using SMS OTP verification."""
    if not verify_sms_otp(phone, otp):
        raise ValueError("Invalid or expired SMS OTP.")

    raw = base64.b64decode(blob_b64)
    if len(raw) < 16:
        raise ValueError("Encrypted blob is not valid.")

    salt = raw[0:16]
    ciphertext = raw[16:]

    fernet_key = derive_fernet_key(pin, otp, salt)
    
    try:
        f = Fernet(fernet_key)
        plaintext_bytes = f.decrypt(ciphertext)
        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# -------------------------------------------------------------------
# Flask Routes
# -------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        otp = request.form.get("otp", "").strip()
        phone = request.form.get("phone", "").strip()
        plaintext = request.form.get("plaintext", "").strip()

        if not (pin and otp and phone and plaintext):
            flash("All fields are required.", "error")
            return redirect(url_for("encrypt"))

        try:
            result = encrypt_message(plaintext, pin, otp, phone)
            flash("Message encrypted successfully!", "success")
            return render_template("encrypt.html", result=result)
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("encrypt"))

    return render_template("encrypt.html")

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        otp = request.form.get("otp", "").strip()
        phone = request.form.get("phone", "").strip()
        blob = request.form.get("blob", "").strip()

        if not (pin and otp and phone and blob):
            flash("All fields are required.", "error")
            return redirect(url_for("decrypt"))

        try:
            plaintext = decrypt_message(blob, pin, otp, phone)
            flash("Message decrypted successfully!", "success")
            return render_template("decrypt.html", result=plaintext)
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("decrypt"))

    return render_template("decrypt.html")

@app.route("/send_otp", methods=["POST"])
def send_otp():
    phone = request.form.get("phone", "").strip()
    if not phone:
        flash("Phone number is required.", "error")
        return redirect(request.referrer or url_for("index"))

    try:
        generate_sms_otp(phone, valid_minutes=5)
        flash("SMS OTP sent! It's valid for 5 minutes.", "success")
    except Exception as e:
        flash(f"Error sending SMS OTP: {e}", "error")

    return redirect(request.referrer or url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
