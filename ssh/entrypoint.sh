#!/bin/bash
# IfSecurity SSH entrypoint
# 1. iptables rate-limit on port 2222 (3 new conn / min / IP)
# 2. Threat intel: load Spamhaus DROP list at boot
# 3. Start rsyslog + sshd

set -e

# ─── 1. Rate-limit on port 2222 (pre-auth defense) ────────────────────────
# Allow up to 3 new connections in 60 s per source IP, drop the rest.
# Anything above MaxStartups will be queued or dropped already, but this
# stops the attacker from even reaching sshd in the first place.
iptables -N IFSECURITY 2>/dev/null || true
iptables -F IFSECURITY

iptables -A IFSECURITY -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --set --name SSH_RATE
iptables -A IFSECURITY -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH_RATE -j DROP

# Hook IFSECURITY chain into INPUT (idempotent)
iptables -C INPUT -j IFSECURITY 2>/dev/null || iptables -I INPUT 1 -j IFSECURITY

# ─── 2. Threat intel: Spamhaus DROP list ──────────────────────────────────
# Loaded once at boot. To refresh: docker restart ssh.
if curl -sf --max-time 10 https://www.spamhaus.org/drop/drop.txt \
     -o /tmp/spamhaus.txt 2>/dev/null; then
  count=0
  while read -r net _; do
    case "$net" in
      [0-9]*)
        iptables -A INPUT -s "$net" -j DROP 2>/dev/null && count=$((count+1))
        ;;
    esac
  done < /tmp/spamhaus.txt
  echo "[entrypoint] Spamhaus DROP: $count networks blocked"
else
  echo "[entrypoint] Spamhaus DROP unreachable, skipping threat intel"
fi

# ─── 3. Start services ────────────────────────────────────────────────────
rsyslogd
exec /usr/sbin/sshd -D
