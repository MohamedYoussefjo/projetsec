#!/bin/bash
# IfSecurity Nginx entrypoint
# 1. iptables rate-limit on port 80 (20 new conn / 60 s / IP)
# 2. Threat intel: load Spamhaus DROP list at boot
# 3. Start nginx

set -e

# ─── 1. Rate-limit on port 80 (pre-auth defense) ──────────────────────────
# Allow up to 20 new connections per 60 s per source IP, drop the rest.
iptables -N IFSECURITY 2>/dev/null || true
iptables -F IFSECURITY

iptables -A IFSECURITY -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m recent --set --name HTTP_RATE
iptables -A IFSECURITY -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 21 --name HTTP_RATE -j DROP

# Hook IFSECURITY chain into INPUT (idempotent)
iptables -C INPUT -j IFSECURITY 2>/dev/null || iptables -I INPUT 1 -j IFSECURITY

# ─── 2. Dedicated ban chain (used by detector) ────────────────────────────
iptables -N NGINX_BAN 2>/dev/null || true
iptables -C INPUT -j NGINX_BAN 2>/dev/null || iptables -I INPUT 2 -j NGINX_BAN

# ─── 3. Threat intel: Spamhaus DROP list ──────────────────────────────────
# Loaded once at boot. To refresh: docker restart nginx.
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

# ─── 4. Start nginx (foreground) ──────────────────────────────────────────
exec nginx -g "daemon off;"
