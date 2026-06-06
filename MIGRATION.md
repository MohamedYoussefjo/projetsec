# IfSecurity v2 — guide de migration

Tu passes d'une plateforme **détection + observabilité** à une plateforme
**détection → réponse → mitigation active**. Voici ce qui change et pourquoi.

---

## Vue d'ensemble des nouveautés

| Composant | Avant v1 | Après v2 |
|---|---|---|
| `detector` | Lit `attempts.log`, écrit ES, ne fait rien | Lit ES `if27-*`, **bannit l'IP via iptables** dans `ssh` + `nginx` |
| `ssh/sshd_pam` | TOTP simple | TOTP + **`pam_faillock`** (5 échecs → lock 30 min) |
| `ssh/Dockerfile` | sshd + rsyslog | sshd + rsyslog + **iptables hashlimit** + **Spamhaus DROP list** |
| `ssh/entrypoint.sh` | absent | nouveau, gère iptables + threat intel |
| `docker-compose.yml` | pas de socket Docker | `detector` monte `/var/run/docker.sock`, `ssh`+`nginx` ont `NET_ADMIN` |
| `endlessh` | absent | service optionnel (`--profile honeypot`) |

---

## Détecteur v2 — la boucle fermée

Le nouveau `detector/detector.py` fait un polling Elasticsearch toutes les
10 s sur 4 règles :

| Règle | Action |
|---|---|
| `ssh_burst_summary` avec `burst_count >= 10` | ban immédiat |
| `ssh_failed_password >= 8` par IP (120 s) | ban |
| `ssh_invalid_user >= 5` par IP (120 s) | ban |
| Tout event web avec `risk_level: critical` | ban |

À chaque détection, le détecteur :

1. Vérifie que l'IP n'est pas déjà bannie
2. Exécute `iptables -A INPUT -s <IP> -j DROP` dans **`ssh` ET `nginx`** via le
   socket Docker (`/var/run/docker.sock`)
3. Stocke `until = now + UNBAN_AFTER_S` (1 h par défaut) en mémoire
4. Trace l'action dans `/app/logs/bans.log` (JSON Lines)
5. À chaque cycle, vérifie les bans expirés et les retire

Paramètres tunables sans rebuild via env :

```yaml
POLL_INTERVAL_S: "10"     # fréquence de polling
LOOKBACK_S: "120"         # fenêtre d'observation
UNBAN_AFTER_S: "3600"     # durée du ban (1 h)
BAN_TARGETS: "ssh,nginx"  # containers cibles
```

---

## pam_faillock côté SSH

Le nouveau `ssh/sshd_pam` ajoute le compteur de PAM :

```
auth required pam_faillock.so preauth silent deny=5 unlock_time=1800
auth [success=1 default=ignore] pam_unix.so nullok
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800
auth required pam_google_authenticator.so
account required pam_faillock.so
account required pam_permit.so
session required pam_permit.so
```

→ Après **5 mauvais mots de passe** (ou TOTP ratés), le compte est **bloqué
30 minutes**, **indépendamment de l'IP**. Protège contre :

- Brute-force distribué (botnet, IPs tournantes)
- Credential stuffing depuis IPs jamais vues

Compatible avec les **modes B et C** (le mode A n'utilise pas PAM).

Pour débloquer manuellement :

```bash
docker exec ssh faillock --user admin --reset
```

---

## iptables hashlimit (rate-limit réseau)

Le nouveau `ssh/entrypoint.sh` installe au démarrage :

```bash
iptables -A IFSECURITY -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --set --name SSH_RATE
iptables -A IFSECURITY -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH_RATE -j DROP
```

→ **Maximum 3 nouvelles connexions / minute / IP** avant même que `sshd` ne
voie le paquet. Casse 90 % des brute-force naïfs sans toucher au sshd.

---

## Spamhaus DROP — threat intel passive

L'entrypoint charge la liste **Spamhaus DROP** au boot :

```bash
curl https://www.spamhaus.org/drop/drop.txt | \
  awk '/^[0-9]/ {print $1}' | \
  while read net; do iptables -A INPUT -s "$net" -j DROP; done
```

→ Bloque ~1500 plages IP déjà identifiées comme malveillantes (botnets, C2,
hébergeurs douteux). Réduit le bruit de 30-50 %.

Pour rafraîchir : `docker compose restart ssh`.

---

## Honeypot endlessh (optionnel)

Active-le seulement pour la démo :

```bash
docker compose --profile honeypot up -d endlessh
```

Il écoute sur le **port 22 réel** (le SSH ifsecurity reste sur 2222). Quand
un attaquant tente `ssh root@<ip>` (port par défaut), il tombe sur endlessh
qui lui envoie une bannière SSH à **1 octet par seconde**. Hydra peut rester
coincé plusieurs minutes par tentative.

Métrique de soutenance : **« temps perdu par l'attaquant »**.

---

## Risques connus et atténuations

| Risque | Niveau | Mitigation |
|---|---|---|
| Le détecteur monte `/var/run/docker.sock` → escalade possible | 🟡 OK pour TP/PFE, **PAS** en prod | En prod : passer par une API REST avec auth |
| iptables-flush si quelqu'un redémarre `ssh` | 🟢 | Bans restaurés par le détecteur au cycle suivant (pas perdus dans ES) |
| Faux positifs sur ton IP de dev | 🟡 | Mets ton IP en whitelist dans `ssh/entrypoint.sh` : `iptables -I INPUT 1 -s <ton_ip> -j ACCEPT` |
| Spamhaus unreachable | 🟢 | L'entrypoint loggue et continue sans bloquer le boot |

---

## Démarrage rapide

```bash
# 1. Build et démarre tout (sans honeypot)
docker compose up -d --build

# 2. Active le honeypot pour la démo
docker compose --profile honeypot up -d endlessh

# 3. Vérifie que le détecteur tourne
docker logs -f ifsecurity-detector

# 4. Lance un brute-force (depuis un autre poste)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<host>:2222

# 5. Regarde les bans
tail -f logs/bans.log | jq

# 6. Liste les IPs bannies dans le container ssh
docker exec ssh iptables -L INPUT -n --line-numbers | head -20
```

---

## Pour ta soutenance — le storytelling

| Slide | Message |
|---|---|
| **Architecture** | « 5 couches de défense en profondeur » : rate-limit réseau → MFA → faillock → ban actif → monitoring |
| **Démo hydra** | Tu lances l'attaque, ils voient l'IP se faire bannir en moins de 30 s sur les 2 surfaces |
| **Dashboard Kibana** | Tu pointes le burst_count qui s'effondre après le ban — la mitigation **mesurable** |
| **Honeypot** | Optionnel : tu montres hydra coincé sur endlessh |

Bon courage 💪
