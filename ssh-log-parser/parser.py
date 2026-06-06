"""
SSH auth.log → JSON Lines parser (compatible Filebeat → Elasticsearch).

Reads /sshlogs/auth.log line by line and emits one JSON event per matched line
to /app/logs/ssh_attempts.log.

Covers: failed/accepted auth (password, publickey, keyboard-interactive,
keyboard-interactive/pam, none), invalid users, AllowUsers/DenyUsers filters,
PAM events (pam_unix, pam_google_authenticator, faillock), connection
open/close/reset, disconnect, max auth attempts, kex/protocol errors, session
open/close, systemd-logind sessions, sudo events.
"""

import json
import os
import re
import socket
import time
from datetime import datetime

AUTH_LOG = os.environ.get("SSH_LOG", "/sshlogs/auth.log")
OUT_LOG = os.environ.get("OUT_LOG", "/app/logs/ssh_attempts.log")
HOSTNAME = socket.gethostname()

# ─── Burst aggregator (rate-limit noise) ────────────────────────────────────
# After the 1st event of a (ip, event_type, username) key is emitted,
# subsequent identical events are collapsed and a single "ssh_burst_summary"
# is emitted after BURST_IDLE_S of silence, or every BURST_MAX_S.
BURST_IDLE_S = 30
BURST_MAX_S = 120
BURST_EVENT_TYPES = {
    "ssh_failed_password",
    "ssh_failed_publickey",
    "ssh_failed_keyboard_interactive",
    "ssh_invalid_user",
    "ssh_max_auth_attempts",
    "pam_auth_failure",
    "pam_user_unknown",
    "pam_totp_invalid",
    "ssh_connection_closed_invalid",
    "ssh_connection_reset_invalid",
    "ssh_bad_protocol",
    "ssh_kex_invalid_identifier",
    "ssh_refused",
}
_bursts = {}  # key -> {"first": ts, "last": ts, "count": int, "sample": event}

# ════════════════════════════════════════════════════════════════════════════
# PATTERNS — order matters: most specific first
# ════════════════════════════════════════════════════════════════════════════
PATTERNS = [
    # ─── AUTH SUCCESS ────────────────────────────────────────────────────────
    {
        "event_type": "ssh_accepted_publickey",
        "auth_method": "publickey",
        "regex": re.compile(
            r"Accepted publickey for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+) ssh2"
            r"(?:: (?P<key_type>\S+) (?P<key_fingerprint>\S+))?"
        ),
    },
    {
        "event_type": "ssh_accepted_password",
        "auth_method": "password",
        "regex": re.compile(
            r"Accepted password for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_accepted_keyboard_interactive",
        "auth_method": "keyboard-interactive",
        "regex": re.compile(
            r"Accepted keyboard-interactive(?:/pam)? for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_accepted_none",
        "auth_method": "none",
        "regex": re.compile(
            r"Accepted none for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },

    # ─── AUTH FAILURE ────────────────────────────────────────────────────────
    {
        "event_type": "ssh_failed_password",
        "auth_method": "password",
        "regex": re.compile(
            r"Failed password for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_failed_publickey",
        "auth_method": "publickey",
        "regex": re.compile(
            r"Failed publickey for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_failed_keyboard_interactive",
        "auth_method": "keyboard-interactive",
        "regex": re.compile(
            r"Failed keyboard-interactive(?:/pam)? for "
            r"(?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_failed_none",
        "auth_method": "none",
        "regex": re.compile(
            r"Failed none for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },

    # ─── INVALID USER / ACL ──────────────────────────────────────────────────
    {
        "event_type": "ssh_invalid_user",
        "regex": re.compile(
            r"Invalid user (?P<username>\S*) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_user_not_allowed",
        "reason": "not in AllowUsers",
        "regex": re.compile(
            r"User (?P<username>\S+) from (?P<source_ip>\S+) "
            r"not allowed because not listed in AllowUsers"
        ),
    },
    {
        "event_type": "ssh_user_denied",
        "reason": "listed in DenyUsers",
        "regex": re.compile(
            r"User (?P<username>\S+) from (?P<source_ip>\S+) "
            r"not allowed because listed in DenyUsers"
        ),
    },
    {
        "event_type": "ssh_group_not_allowed",
        "reason": "group not in AllowGroups",
        "regex": re.compile(
            r"User (?P<username>\S+) from (?P<source_ip>\S+) "
            r"not allowed because none of user's groups are listed in AllowGroups"
        ),
    },

    # ─── MAX AUTH ATTEMPTS ───────────────────────────────────────────────────
    {
        "event_type": "ssh_max_auth_attempts",
        "regex": re.compile(
            r"error: maximum authentication attempts exceeded for "
            r"(?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },

    # ─── PAM EVENTS ──────────────────────────────────────────────────────────
    {
        "event_type": "pam_auth_failure",
        "auth_method": "pam",
        "regex": re.compile(
            r"pam_unix\(sshd:auth\): authentication failure;.*?"
            r"rhost=(?P<source_ip>\S+)(?:\s+user=(?P<username>\S+))?"
        ),
    },
    {
        "event_type": "pam_user_unknown",
        "auth_method": "pam",
        "regex": re.compile(r"pam_unix\(sshd:auth\): check pass; user unknown"),
    },
    {
        "event_type": "pam_totp_invalid",
        "auth_method": "totp",
        "regex": re.compile(
            r"pam_google_authenticator.*Invalid verification code"
            r"(?: for (?P<username>\S+))?"
        ),
    },
    {
        "event_type": "pam_totp_valid",
        "auth_method": "totp",
        "regex": re.compile(
            r"pam_google_authenticator.*Found valid verification code"
            r"(?: for (?P<username>\S+))?"
        ),
    },
    {
        "event_type": "pam_account_locked",
        "regex": re.compile(
            r"pam_faillock.*Consecutive login failures for user (?P<username>\S+)"
        ),
    },

    # ─── SESSION (PAM) ───────────────────────────────────────────────────────
    {
        "event_type": "ssh_session_opened",
        "regex": re.compile(
            r"pam_unix\(sshd:session\): session opened for user (?P<username>\S+)"
        ),
    },
    {
        "event_type": "ssh_session_closed",
        "regex": re.compile(
            r"pam_unix\(sshd:session\): session closed for user (?P<username>\S+)"
        ),
    },

    # ─── SYSTEMD-LOGIND ──────────────────────────────────────────────────────
    {
        "event_type": "logind_session_new",
        "regex": re.compile(
            r"systemd-logind.*New session (?P<session_id>\S+) of user (?P<username>\S+)"
        ),
    },
    {
        "event_type": "logind_session_logout",
        "regex": re.compile(
            r"systemd-logind.*Session (?P<session_id>\S+) logged out"
        ),
    },

    # ─── DISCONNECT ──────────────────────────────────────────────────────────
    {
        "event_type": "ssh_disconnect_authenticating",
        "regex": re.compile(
            r"Disconnected from authenticating user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_disconnect_invalid",
        "regex": re.compile(
            r"Disconnected from invalid user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_disconnect_user",
        "regex": re.compile(
            r"Disconnected from user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_received_disconnect",
        "regex": re.compile(
            r"Received disconnect from (?P<source_ip>\S+) port (?P<source_port>\d+)"
            r"(?::\d+:\s+(?P<reason>.+?))?(?:\s+\[preauth\])?$"
        ),
    },

    # ─── CONNECTION ──────────────────────────────────────────────────────────
    {
        "event_type": "ssh_connection_open",
        "regex": re.compile(
            r"Connection from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_closed_authenticating",
        "regex": re.compile(
            r"Connection closed by authenticating user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_closed_invalid",
        "regex": re.compile(
            r"Connection closed by invalid user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_closed",
        "regex": re.compile(
            r"Connection closed by (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_reset_authenticating",
        "regex": re.compile(
            r"Connection reset by authenticating user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_reset_invalid",
        "regex": re.compile(
            r"Connection reset by invalid user (?P<username>\S+) "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_connection_reset",
        "regex": re.compile(
            r"Connection reset by (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },

    # ─── PROTOCOL / KEX ERRORS (scanner / fingerprinter) ────────────────────
    {
        "event_type": "ssh_bad_protocol",
        "regex": re.compile(
            r"Bad protocol version identification '(?P<banner>[^']*)' "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    },
    {
        "event_type": "ssh_kex_invalid_identifier",
        "regex": re.compile(
            r"kex_exchange_identification:.*client sent invalid protocol identifier "
            r'"(?P<banner>[^"]*)"'
        ),
    },
    {
        "event_type": "ssh_kex_connection_closed",
        "regex": re.compile(
            r"kex_exchange_identification:.*Connection closed by remote host"
        ),
    },
    {
        "event_type": "ssh_banner_invalid",
        "regex": re.compile(
            r"banner exchange: Connection from (?P<source_ip>\S+) port "
            r"(?P<source_port>\d+): invalid format"
        ),
    },

    # ─── REFUSED ─────────────────────────────────────────────────────────────
    {
        "event_type": "ssh_refused",
        "regex": re.compile(r"refused connect from (?P<source_ip>\S+)"),
    },

    # ─── SUDO (souvent dans auth.log) ────────────────────────────────────────
    {
        "event_type": "sudo_command",
        "regex": re.compile(
            r"sudo:\s+(?P<username>\S+)\s+:\s+TTY=(?P<tty>\S+)\s*;\s*"
            r"PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*"
            r"COMMAND=(?P<command>.+)"
        ),
    },
    {
        "event_type": "sudo_auth_failure",
        "regex": re.compile(
            r"sudo:.*pam_unix\(sudo:auth\): authentication failure;.*"
            r"user=(?P<username>\S+)"
        ),
    },
]


# ════════════════════════════════════════════════════════════════════════════
# RISK CLASSIFICATION
# ════════════════════════════════════════════════════════════════════════════
RISK_MAP = {
    # critical → certain compromise indicator
    "ssh_accepted_password": "low",   # password auth ok but auth.log shows it
    "ssh_accepted_publickey": "low",
    "ssh_accepted_keyboard_interactive": "low",
    "ssh_accepted_none": "critical",  # auth without credentials = misconfig
    "sudo_command": "medium",

    # high → brute force / probing
    "ssh_failed_password": "high",
    "ssh_failed_publickey": "high",
    "ssh_failed_keyboard_interactive": "high",
    "ssh_failed_none": "high",
    "ssh_invalid_user": "high",
    "ssh_max_auth_attempts": "high",
    "pam_auth_failure": "high",
    "pam_user_unknown": "high",
    "pam_totp_invalid": "high",
    "pam_account_locked": "high",
    "sudo_auth_failure": "high",
    "ssh_user_not_allowed": "high",
    "ssh_user_denied": "high",
    "ssh_group_not_allowed": "high",
    "ssh_bad_protocol": "high",
    "ssh_kex_invalid_identifier": "high",
    "ssh_banner_invalid": "high",
    "ssh_refused": "high",

    # medium → suspicious but ambiguous
    "ssh_disconnect_authenticating": "medium",
    "ssh_disconnect_invalid": "medium",
    "ssh_connection_closed_authenticating": "medium",
    "ssh_connection_closed_invalid": "medium",
    "ssh_connection_reset_authenticating": "medium",
    "ssh_connection_reset_invalid": "medium",
    "ssh_kex_connection_closed": "medium",

    # low → benign telemetry
    "ssh_connection_open": "low",
    "ssh_connection_closed": "low",
    "ssh_connection_reset": "low",
    "ssh_received_disconnect": "low",
    "ssh_disconnect_user": "low",
    "ssh_session_opened": "low",
    "ssh_session_closed": "low",
    "logind_session_new": "low",
    "logind_session_logout": "low",
    "pam_totp_valid": "low",
}

SUCCESS_EVENTS = {
    "ssh_accepted_password",
    "ssh_accepted_publickey",
    "ssh_accepted_keyboard_interactive",
    "ssh_accepted_none",
    "pam_totp_valid",
    "ssh_session_opened",
}


# ════════════════════════════════════════════════════════════════════════════
# CORE
# ════════════════════════════════════════════════════════════════════════════
def parse_line(line: str):
    """Match `line` against every pattern; return a dict or None."""
    for p in PATTERNS:
        m = p["regex"].search(line)
        if not m:
            continue

        data = m.groupdict()
        event_type = p["event_type"]
        invalid_user = bool(data.get("invalid"))

        # Default port as int when present
        try:
            source_port = int(data["source_port"]) if data.get("source_port") else None
        except (TypeError, ValueError):
            source_port = None

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": HOSTNAME,
            "attack_surface": "ssh",
            "app_service": "openssh",
            "event_type": event_type,
            "action": event_type,
            "auth_method": p.get("auth_method"),
            "username": data.get("username") or None,
            "source_ip": data.get("source_ip") or None,
            "source_port": source_port,
            "invalid_user": invalid_user,
            "preauth": "[preauth]" in line,
            "password_success": event_type == "ssh_accepted_password",
            "final_auth_success": event_type in SUCCESS_EVENTS,
            "risk_level": RISK_MAP.get(event_type, "medium"),
            "key_type": data.get("key_type"),
            "key_fingerprint": data.get("key_fingerprint"),
            "session_id": data.get("session_id"),
            "reason": data.get("reason") or p.get("reason"),
            "banner": data.get("banner"),
            "tty": data.get("tty"),
            "pwd": data.get("pwd"),
            "target_user": data.get("target_user"),
            "command": data.get("command"),
            "raw_log": line.strip(),
        }
    return None


def follow(path: str):
    """Tail -F: stream new lines, re-open on rotation or truncation."""
    while not os.path.exists(path):
        print(f"[parser] waiting for {path}…", flush=True)
        time.sleep(1)

    f = open(path, "r", errors="ignore")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.5)
        try:
            current_inode = os.stat(path).st_ino
            current_size = os.stat(path).st_size
            if current_inode != inode or current_size < f.tell():
                f.close()
                return  # outer loop will re-open
        except FileNotFoundError:
            f.close()
            return


def _emit(event):
    """Write an event to disk and stdout."""
    event = {k: v for k, v in event.items() if v is not None}
    with open(OUT_LOG, "a", encoding="utf-8") as out:
        out.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(
        f"[parser] {event['event_type']:<35} "
        f"ip={event.get('source_ip')} "
        f"user={event.get('username')} "
        f"risk={event.get('risk_level')}"
        + (f" count={event['burst_count']}" if "burst_count" in event else ""),
        flush=True,
    )


def _maybe_aggregate(event):
    """
    Return True if the event was emitted live, False if it was swallowed
    into a burst counter (waiting to be flushed by flush_bursts()).
    """
    if event["event_type"] not in BURST_EVENT_TYPES:
        return True  # not a burst-prone event → emit as-is

    key = (
        event.get("source_ip"),
        event["event_type"],
        event.get("username"),
    )
    now = time.time()
    state = _bursts.get(key)

    if state is None:
        # First occurrence in window → emit live AND start counting
        _bursts[key] = {"first": now, "last": now, "count": 1, "sample": event}
        return True

    # Same key already counted → swallow, just update counter
    state["last"] = now
    state["count"] += 1
    return False


def flush_bursts(force=False):
    """Emit ssh_burst_summary events for keys idle for BURST_IDLE_S
    (or max-aged BURST_MAX_S), then prune. force=True flushes everything."""
    now = time.time()
    for key in list(_bursts.keys()):
        state = _bursts[key]
        idle = now - state["last"]
        age = now - state["first"]
        if not force and idle < BURST_IDLE_S and age < BURST_MAX_S:
            continue
        if state["count"] > 1:
            sample = state["sample"]
            summary = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "host": HOSTNAME,
                "attack_surface": "ssh",
                "app_service": "openssh",
                "event_type": "ssh_burst_summary",
                "burst_of": sample["event_type"],
                "auth_method": sample.get("auth_method"),
                "username": sample.get("username"),
                "source_ip": sample.get("source_ip"),
                "burst_count": state["count"],
                "burst_first_seen": datetime.utcfromtimestamp(state["first"]).isoformat() + "Z",
                "burst_last_seen": datetime.utcfromtimestamp(state["last"]).isoformat() + "Z",
                "burst_duration_s": round(state["last"] - state["first"], 2),
                "burst_rate_per_min": round(state["count"] / max((state["last"] - state["first"]) / 60, 1 / 60), 1),
                "risk_level": "critical" if state["count"] >= 20 else "high",
            }
            _emit(summary)
        del _bursts[key]


def main():
    os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
    print(f"[parser] tailing {AUTH_LOG} → {OUT_LOG}", flush=True)

    last_flush = time.time()
    while True:
        try:
            for line in follow(AUTH_LOG):
                if not any(k in line for k in ("sshd", "pam_", "sudo", "systemd-logind")):
                    continue
                event = parse_line(line)
                if not event:
                    continue
                if _maybe_aggregate(event):
                    _emit(event)

                # opportunistic flush every 5 s
                if time.time() - last_flush > 5:
                    flush_bursts()
                    last_flush = time.time()
        except Exception as e:
            print(f"[parser] error: {e}, flushing & retrying in 3s", flush=True)
            flush_bursts(force=True)
            time.sleep(3)


if __name__ == "__main__":
    main()

