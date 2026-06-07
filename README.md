# 🛡 IfSecurity

Plateforme de détection, mitigation active et observabilité contre les attaques par force brute SSH et Web.

---

## 📦 Partie 1 — Installation et configuration

Avant de lancer la stack avec `docker compose up -d --build`, il faut générer ses propres secrets (clés SSH, TOTP, reCAPTCHA) pour ne pas réutiliser ceux de l'auteur initial du projet.

> 📄 **Documentation complète avec captures** : [`setupautomatise.docx`](./setupautomatise.docx)

---

### Étape 1 — Génération des clés SSH

**Sur Ubuntu/Linux :**

```bash
ssh-keygen -t ed25519
# Clés créées dans ~/.ssh/id_ed25519 (privée) et ~/.ssh/id_ed25519.pub (publique)
```

**Sur Windows (PowerShell) :**

```powershell
ssh-keygen -t ed25519
# Clés créées dans %USERPROFILE%\.ssh\id_ed25519[.pub]
```

Affiche ta clé publique :

```bash
cat ~/.ssh/id_ed25519.pub
```

→ Copie cette ligne, tu vas la coller dans `setup.sh`.

---

### Étape 2 — Création du secret TOTP

Dans Google Authenticator :
1. Appuie sur **+** en bas
2. **Saisir une clé de configuration**
3. Nom de code : `IfSecurity-SSH` (ou ce que tu veux)
4. Ta clé : choisis une chaîne de **16 caractères base32** (A-Z et 2-7)
   - Exemple : `JBSWY3DPEHPK3PXP`
5. Type de clé : **Basé sur l'heure**
6. **Ajouter**

→ Garde cette même clé sous la main, tu vas la coller dans `setup.sh`.

---

### Étape 3 — Création des clés reCAPTCHA

Ouvre [https://www.google.com/recaptcha/admin/create](https://www.google.com/recaptcha/admin/create)

1. **Libellé** : `IfSecurity`
2. **Type** : reCAPTCHA v2 → « Case à cocher Je ne suis pas un robot »
3. **Domaines** : `localhost`, `127.0.0.1`, ton IP (ex : `192.168.80.129`)
4. **Submit**

Google fournit :
- Une **clé de site** (publique, commence par `6L…`)
- Une **clé secrète** (privée, commence par `6L…`)

→ Garde-les sous la main pour `setup.sh`.

---

### Étape 4 — Lancement automatique

Édite le fichier [`setup.sh`](./setup.sh) et remplis les 4 variables en haut :

```bash
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... ton-user@ta-machine"
TOTP_SECRET="JBSWY3DPEHPK3PXP"
RECAPTCHA_SITE_KEY="6LeQfBItAAAAAOy4v4hV4ceO-rS5rwY2UHohMMJa"
RECAPTCHA_SECRET_KEY="6LeQfBItAAAAANE_eZCrfCldmQqYghJSsGezpshI"
```

Puis lance :

```bash
chmod +x setup.sh
./setup.sh
```

Le script fait automatiquement :

| # | Action | Commande |
|---|---|---|
| 1 | Injecte ta clé publique SSH | `echo > ssh/authorized_keys` |
| 2 | Écrit le secret TOTP | `echo > ssh/google_authenticator` |
| 3 | Met à jour `login-api/app.py` | `sed -i` (MFA_SECRET + RECAPTCHA_SECRET) |
| 4 | Met à jour `front-end/login.html` | `sed -i` (data-sitekey) |
| 5 | Donne les permissions sur `logs/` | `sudo chmod -R 777 ./logs` |
| 6 | Construit et démarre les conteneurs | `docker compose up -d --build` |
| 7 | Importe les dashboards Kibana | `curl -X POST .../api/saved_objects/_import` |
| 8 | Affiche le récapitulatif | URLs + commande SSH |

---

### Vérification

Après l'exécution du script, tu dois voir tous les conteneurs UP :

```bash
docker compose ps
```

Et accéder aux services :

| Service | URL |
|---|---|
| **Web login** | http://localhost |
| **Kibana** | http://localhost:5601 |
| **SSH (port 2222)** | `ssh -p 2222 admin@localhost` |

---
