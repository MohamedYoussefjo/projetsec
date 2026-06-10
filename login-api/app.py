from flask import Flask, request, jsonify, make_response, session
from datetime import datetime
from collections import defaultdict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import json
import os
import time
import pyotp
import requests

app = Flask(__name__)
app.secret_key = "secret-key"

VALID_USER = "admin"
VALID_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=2$cORJH7OHf9yTlYvs1LblpQ$Xc9Hj+BJi2V73/QhuLkMRfO/DHpUxWKG7cS3x/CVwyM"

# Pepper côté serveur — ajouté à chaque mot de passe AVANT hashing.
# À conserver dans un vault (variable d'env / Docker secret), jamais dans le repo.
# Sans le pepper, un hash volé reste incrackable.
PEPPER = os.environ.get("PASSWORD_PEPPER", "if27-default-pepper-CHANGE-ME")

# ─── Honey accounts (comptes leurres) ───────────────────────────────────
# Toute tentative sur l'un de ces comptes déclenche un PERMA-BAN via R7.
HONEY_ACCOUNTS = {
    "backup_admin":  "$argon2id$v=19$m=65536,t=3,p=2$qRNndq5HaHjHmmuYOSLsYA$PihcG4NqBjh6awBO/EMzMNaU1+x5BmZHgsDoMiUh2Ow",
    "audit_service": "$argon2id$v=19$m=65536,t=3,p=2$mFHNvl6qo9qzzyO+erVJTQ$XUOvGec5Eh3okNNGBv87xbzW3Hzyi7JY6YRZv3WA8+Y",
    "old_admin":     "$argon2id$v=19$m=65536,t=3,p=2$WLcAKHuPfnpqrS/BMLYcxQ$9rKljXNAn5BP5cteRnhtRpNj8+l6sJ9EkWEXq951bg0",
}

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2
)

MFA_SECRET = "JBSWY3DPEHPK3PXP"
RECAPTCHA_SECRET = "6Ld0aPwsAAAAAP4b6iLliO9J4s3O9168EW-CkoST"

LOG_FILE = "/app/logs/attempts.log"

account_failures = defaultdict(int)
account_locked_until = defaultdict(float)
account_lock_level = defaultdict(lambda: "none")

ip_failures = defaultdict(int)
ip_next_allowed_time = defaultdict(float)


def verify_password(password, stored_hash):
    """Vérifie un mot de passe en lui ajoutant le pepper avant Argon2id."""
    try:
        return ph.verify(stored_hash, PEPPER + password)
    except (VerifyMismatchError, VerificationError):
        return False


def utc_now():
    return datetime.utcnow().isoformat()


def get_client_ip():
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP")
        or request.remote_addr
        or "unknown"
    )


def calculate_ip_delay(failed_count):
    if failed_count < 3:
        return 0
    return min(failed_count * 5, 60)


def get_risk_level(password_success, acc_failures, ip_fails):
    if password_success:
        return "medium"

    if acc_failures >= 8 or ip_fails >= 10:
        return "critical"

    if acc_failures >= 5 or ip_fails >= 6:
        return "high"

    if acc_failures >= 3 or ip_fails >= 3:
        return "medium"

    return "low"


def apply_aggressive_lockout(username, now):
    failures = account_failures[username]

    if failures >= 8:
        account_locked_until[username] = float(now + 60 * 60)
        account_lock_level[username] = "aggressive_lock_1h"

    elif failures >= 5:
        account_locked_until[username] = float(now + 15 * 60)
        account_lock_level[username] = "hard_lock_15min"

    elif failures >= 3:
        account_locked_until[username] = float(now + 5 * 60)
        account_lock_level[username] = "soft_lock_5min"


def log_event(event):
    os.makedirs("/app/logs", exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def base_event():
    return {
        "timestamp": utc_now(),
        "attack_surface": "web_login",
        "app_service": "ifsecurity-login",

        "source_ip": get_client_ip(),
        "http_user_agent": request.headers.get("User-Agent", ""),
        "http_method": request.method,
        "http_path": request.path,
        "http_host": request.headers.get("Host", ""),
        "http_referer": request.headers.get("Referer", ""),
        "http_origin": request.headers.get("Origin", ""),
        "x_real_ip": request.headers.get("X-Real-IP", ""),
        "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),

        "mac_address": "not_available_over_http"
    }


def verify_recaptcha(username):
    recaptcha_response = request.form.get("g-recaptcha-response", "")

    if not recaptcha_response:
        event = base_event()
        event.update({
            "event_type": "recaptcha_missing",
            "action": "recaptcha_missing",
            "username": username,
            "password_success": False,
            "final_auth_success": False,
            "risk_level": "medium"
        })
        log_event(event)
        return False

    try:
        verify = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": RECAPTCHA_SECRET,
                "response": recaptcha_response,
                "remoteip": get_client_ip()
            },
            timeout=5
        )

        captcha_result = verify.json()
        return bool(captcha_result.get("success", False))

    except Exception as e:
        event = base_event()
        event.update({
            "event_type": "recaptcha_error",
            "action": "recaptcha_error",
            "username": username,
            "password_success": False,
            "final_auth_success": False,
            "risk_level": "high",
            "error_message": str(e)
        })
        log_event(event)
        return False


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    ip = get_client_ip()
    now = time.time()

    if not verify_recaptcha(username):
        event = base_event()
        event.update({
            "event_type": "recaptcha_failed",
            "action": "recaptcha_failed",
            "username": username,
            "password_success": False,
            "final_auth_success": False,
            "risk_level": "medium"
        })
        log_event(event)

        return jsonify({
            "status": "failed",
            "message": "reCAPTCHA verification failed."
        }), 400

    # ─── Honey account : risk_level=honey → R7 du detector = PERMA-BAN ──
    if username in HONEY_ACCOUNTS:
        honey_password_match = verify_password(password, HONEY_ACCOUNTS[username])

        event = base_event()
        event.update({
            "event_type": "honey_account_triggered",
            "action": "honey_account_triggered",
            "username": username,
            "honey_password_match": bool(honey_password_match),
            "risk_level": "honey",
            "message": "Tentative de connexion sur un compte leurre",
            "password_success": False,
            "final_auth_success": False,
            "log_source": "web"
        })
        log_event(event)

        return jsonify({
            "status": "failed",
            "message": "Invalid username or password."
        }), 401

    if now < ip_next_allowed_time[ip]:
        retry_after = int(ip_next_allowed_time[ip] - now)

        event = base_event()
        event.update({
            "event_type": "rate_limit",
            "action": "ip_rate_limited",
            "risk_level": "high",
            "username": username,
            "password_success": False,
            "final_auth_success": False,
            "ip_rate_limited": True,
            "retry_after": retry_after,
            "ip_failures": int(ip_failures[ip]),
            "ip_next_allowed_time": float(ip_next_allowed_time[ip]),
            "account_locked": False,
            "account_failures": int(account_failures[username]),
            "account_lock_level": str(account_lock_level[username]),
            "account_locked_until": float(account_locked_until[username])
        })

        log_event(event)

        response = make_response(jsonify({
            "status": "blocked",
            "message": f"Too many attempts. Retry after {retry_after} seconds."
        }), 429)

        response.headers["Retry-After"] = str(retry_after)
        return response

    if now < account_locked_until[username]:
        retry_after = int(account_locked_until[username] - now)

        event = base_event()
        event.update({
            "event_type": "account_lockout",
            "action": "account_locked",
            "risk_level": "critical",
            "username": username,
            "password_success": False,
            "final_auth_success": False,
            "account_locked": True,
            "account_failures": int(account_failures[username]),
            "account_lock_level": str(account_lock_level[username]),
            "account_locked_until": float(account_locked_until[username]),
            "retry_after": retry_after,
            "ip_rate_limited": False,
            "ip_failures": int(ip_failures[ip]),
            "ip_next_allowed_time": float(ip_next_allowed_time[ip])
        })

        log_event(event)

        response = make_response(jsonify({
            "status": "locked",
            "message": "Account temporarily locked.",
            "lock_level": account_lock_level[username]
        }), 423)

        response.headers["Retry-After"] = str(retry_after)
        return response

    password_success = username == VALID_USER and verify_password(password, VALID_PASSWORD_HASH)

    if not password_success:
        account_failures[username] += 1
        ip_failures[ip] += 1

        apply_aggressive_lockout(username, now)

        delay = calculate_ip_delay(ip_failures[ip])

        if delay > 0:
            ip_next_allowed_time[ip] = float(now + delay)

    else:
        account_failures[username] = 0
        account_locked_until[username] = 0.0
        account_lock_level[username] = "none"

        ip_failures[ip] = 0
        ip_next_allowed_time[ip] = 0.0

    risk_level = get_risk_level(
        password_success,
        account_failures[username],
        ip_failures[ip]
    )

    event = base_event()
    event.update({
        "event_type": "authentication_attempt",
        "action": "login_attempt",

        "username": username,
        "password_length": int(len(password)),
        "password_success": bool(password_success),
        "final_auth_success": False,

        "risk_level": str(risk_level),

        "account_failures": int(account_failures[username]),
        "account_lock_level": str(account_lock_level[username]),
        "account_locked_until": float(account_locked_until[username]),
        "account_locked": bool(time.time() < account_locked_until[username]),

        "ip_failures": int(ip_failures[ip]),
        "ip_next_allowed_time": float(ip_next_allowed_time[ip]),
        "ip_delay_seconds": int(calculate_ip_delay(ip_failures[ip])),
        "ip_rate_limited": False
    })

    log_event(event)

    if password_success:
        session["pending_mfa_user"] = username
        session["mfa_attempt_used"] = False

        event = base_event()
        event.update({
            "event_type": "mfa_required",
            "action": "mfa_required",
            "username": username,
            "password_success": True,
            "final_auth_success": False,
            "risk_level": "medium",
            "account_failures": int(account_failures[username]),
            "account_lock_level": str(account_lock_level[username]),
            "account_locked_until": float(account_locked_until[username]),
            "account_locked": False,
            "ip_failures": int(ip_failures[ip]),
            "ip_next_allowed_time": float(ip_next_allowed_time[ip]),
            "ip_rate_limited": False
        })

        log_event(event)

        return jsonify({
            "status": "mfa_required",
            "message": "Password correct. MFA required.",
            "redirect": "/mfa.html"
        })

    return jsonify({
        "status": "failed",
        "message": "Invalid username or password.",
        "failures": int(account_failures[username]),
        "lock_level": str(account_lock_level[username]),
        "risk_level": str(risk_level)
    }), 401


@app.route("/mfa", methods=["POST"])
def mfa_verify():
    if "pending_mfa_user" not in session:
        return jsonify({
            "status": "failed",
            "message": "No pending MFA session. Please login again."
        }), 401

    if session.get("mfa_attempt_used"):
        session.pop("pending_mfa_user", None)
        session.pop("mfa_attempt_used", None)

        return jsonify({
            "status": "failed",
            "message": "MFA session already used. Please login again."
        }), 401

    session["mfa_attempt_used"] = True

    code = request.form.get("code", "")
    username = session["pending_mfa_user"]
    ip = get_client_ip()

    totp = pyotp.TOTP(MFA_SECRET)

    if totp.verify(code, valid_window=1):
        session["user"] = username
        session.pop("pending_mfa_user", None)
        session.pop("mfa_attempt_used", None)

        event = base_event()
        event.update({
            "event_type": "mfa_success",
            "action": "mfa_success",
            "username": username,
            "password_success": True,
            "final_auth_success": True,
            "risk_level": "low",
            "mfa_attempts_allowed": 1,
            "mfa_attempt_used": True
        })

        log_event(event)

        return jsonify({
            "status": "success",
            "message": "Login successful with MFA."
        })

    session.pop("pending_mfa_user", None)
    session.pop("mfa_attempt_used", None)

    event = base_event()
    event.update({
        "event_type": "mfa_failed",
        "action": "mfa_failed_session_revoked",
        "username": username,
        "password_success": True,
        "final_auth_success": False,
        "mfa_attempts_allowed": 1,
        "mfa_attempt_used": True,
        "risk_level": "critical"
    })

    log_event(event)

    return jsonify({
        "status": "failed",
        "message": "Invalid MFA code. Session revoked. Please login again."
    }), 401


app.run(host="0.0.0.0", port=5000)
