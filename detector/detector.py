"""
IfSecurity Detector v2 — close the detection→response loop.

Reads structured events from Elasticsearch (if27-web-* + if27-ssh-*),
computes risk per source IP, and bans offending IPs by exec-ing
`iptables -A INPUT -s <ip> -j DROP` inside the ssh and nginx containers
via the Docker socket.

Bans are time-limited (UNBAN_AFTER_S, default 1h) and audited to
/app/logs/bans.log (JSON Lines).
"""

import json
import os
import time
from datetime import datetime

import docker
from elasticsearch import Elasticsearch

# ─── Config ─────────────────────────────────────────────────────────────────
ES_URL          = os.environ.get("ES_URL", "http://elasticsearch:9200")
INDEX_PATTERN   = os.environ.get("INDEX_PATTERN", "if27-*")
POLL_INTERVAL_S = int(os.environ.get("POLL_INTERVAL_S", "10"))
LOOKBACK_S      = int(os.environ.get("LOOKBACK_S", "120"))
UNBAN_AFTER_S   = int(os.environ.get("UNBAN_AFTER_S", "3600"))
BAN_LOG         = os.environ.get("BAN_LOG", "/app/logs/bans.log")

# Containers where the iptables ban will be installed
BAN_TARGETS = [t.strip() for t in os.environ.get(
    "BAN_TARGETS", "ssh,nginx"
).split(",") if t.strip()]

# Detection rules. Each rule -> ES query. If a `count_threshold` is set,
# offenders are aggregated by source_ip; otherwise every matched doc bans.
BAN_RULES = [
    {
        "name": "ssh_burst_summary >=3",
        "count_threshold": None,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "ssh_burst_summary"}},
                    {"range": {"burst_count": {"gte": 3}}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_S}s"}}},
                ]
            }
        },
    },
    {
        "name": "ssh_failed_password >=8 per IP",
        "count_threshold": 8,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "ssh_failed_password"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_S}s"}}},
                ]
            }
        },
    },
    {
        "name": "ssh_invalid_user >=5 per IP",
        "count_threshold": 5,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "ssh_invalid_user"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_S}s"}}},
                ]
            }
        },
    },
    {
        "name": "web critical risk_level",
        "count_threshold": None,
        "query": {
            "bool": {
                "must": [
                    {"term": {"log_source": "web"}},
                    {"term": {"risk_level": "critical"}},
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_S}s"}}},
                ]
            }
        },
    },
]

# ─── Globals ───────────────────────────────────────────────────────────────
es = Elasticsearch(ES_URL, request_timeout=10)
dk = docker.from_env()
banned = {}   # ip -> {"until": ts, "reason": str, "containers": [str]}


# ─── Helpers ───────────────────────────────────────────────────────────────
def log_event(event):
    os.makedirs(os.path.dirname(BAN_LOG), exist_ok=True)
    with open(BAN_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"


def install_ban(ip):
    """Add iptables DROP rule on each target container."""
    successes = []
    for name in BAN_TARGETS:
        try:
            container = dk.containers.get(name)
            # Idempotent: check first, add if missing
            check = container.exec_run(f"iptables -C INPUT -s {ip} -j DROP")
            if check.exit_code != 0:
                container.exec_run(f"iptables -A INPUT -s {ip} -j DROP")
            successes.append(name)
        except docker.errors.NotFound:
            print(f"[detector] container '{name}' not found, skipping",
                  flush=True)
        except Exception as e:
            print(f"[detector] iptables on {name} for {ip} failed: {e}",
                  flush=True)
    return successes


def remove_ban(ip, containers):
    for name in containers:
        try:
            container = dk.containers.get(name)
            container.exec_run(f"iptables -D INPUT -s {ip} -j DROP")
        except Exception:
            pass


def ban(ip, reason):
    if ip in banned or not ip or ip == "unknown":
        return False

    installed_on = install_ban(ip)
    if not installed_on:
        return False

    until = time.time() + UNBAN_AFTER_S
    banned[ip] = {
        "until": until,
        "reason": reason,
        "containers": installed_on,
    }
    log_event({
        "timestamp": utc_now_iso(),
        "action": "ban",
        "source_ip": ip,
        "reason": reason,
        "containers": installed_on,
        "ban_duration_s": UNBAN_AFTER_S,
        "expires_at": datetime.utcfromtimestamp(until).isoformat() + "Z",
    })
    print(f"[detector] BAN {ip} ({reason}) on {installed_on}", flush=True)
    return True


def cleanup_expired():
    now = time.time()
    for ip in list(banned.keys()):
        if banned[ip]["until"] <= now:
            remove_ban(ip, banned[ip]["containers"])
            log_event({
                "timestamp": utc_now_iso(),
                "action": "unban",
                "source_ip": ip,
                "reason": "ttl_expired",
            })
            print(f"[detector] UNBAN {ip} (ttl expired)", flush=True)
            del banned[ip]


# ─── Detection cycle ───────────────────────────────────────────────────────
def evaluate():
    for rule in BAN_RULES:
        try:
            if rule["count_threshold"] is None:
                resp = es.search(
                    index=INDEX_PATTERN,
                    size=100,
                    query=rule["query"],
                    _source=["source_ip"],
                )
                for hit in resp["hits"]["hits"]:
                    ip = hit["_source"].get("source_ip")
                    ban(ip, rule["name"])
            else:
                resp = es.search(
                    index=INDEX_PATTERN,
                    size=0,
                    query=rule["query"],
                    aggs={
                        "by_ip": {
                            "terms": {
                                "field": "source_ip.keyword",
                                "size": 100,
                                "min_doc_count": rule["count_threshold"],
                            }
                        }
                    },
                )
                buckets = resp["aggregations"]["by_ip"]["buckets"]
                for b in buckets:
                    ban(b["key"], f"{rule['name']} (count={b['doc_count']})")
        except Exception as e:
            print(f"[detector] rule '{rule['name']}' failed: {e}", flush=True)


def wait_for_es():
    while True:
        try:
            if es.ping():
                print("[detector] connected to Elasticsearch", flush=True)
                return
        except Exception as e:
            print(f"[detector] waiting for ES: {e}", flush=True)
        time.sleep(3)


def main():
    print(f"[detector] booting — targets={BAN_TARGETS} "
          f"poll={POLL_INTERVAL_S}s lookback={LOOKBACK_S}s "
          f"unban_after={UNBAN_AFTER_S}s", flush=True)
    wait_for_es()

    while True:
        try:
            evaluate()
            cleanup_expired()
        except Exception as e:
            print(f"[detector] cycle error: {e}", flush=True)
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    main()
