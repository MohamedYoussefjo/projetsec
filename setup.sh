#!/bin/bash
# Setup IfSecurity : édite les variables ci-dessous puis lance ./setup.sh

# === 1. Variables à éditer ===

SSH_PUBLIC_KEY="met-ta-clé-publique"
TOTP_SECRET="JBSWY3DPEHPK3PXP"
RECAPTCHA_SITE_KEY="6Ld0aPwsAAAAAEHsFPzolGiecXHEYulyW3HNKZuT"
RECAPTCHA_SECRET_KEY="6Ld0aPwsAAAAAP4b6iLliO9J4s3O9168EW-CkoST"


# === 2. Injection de la clé publique SSH ===

echo "$SSH_PUBLIC_KEY" > ssh/authorized_keys
chmod 644 ssh/authorized_keys


# === 3. Écriture du secret TOTP ===

echo "$TOTP_SECRET" > ssh/google_authenticator
echo '" RATE_LIMIT 3 30' >> ssh/google_authenticator
echo '" WINDOW_SIZE 3' >> ssh/google_authenticator
echo '" DISALLOW_REUSE' >> ssh/google_authenticator
echo '" TOTP_AUTH' >> ssh/google_authenticator
chmod 644 ssh/google_authenticator


# === 4. Mise à jour de login-api/app.py ===

sed -i "s|MFA_SECRET = \".*\"|MFA_SECRET = \"$TOTP_SECRET\"|" login-api/app.py
sed -i "s|RECAPTCHA_SECRET = \".*\"|RECAPTCHA_SECRET = \"$RECAPTCHA_SECRET_KEY\"|" login-api/app.py


# === 5. Mise à jour de front-end/login.html ===

sed -i "s|data-sitekey=\".*\"|data-sitekey=\"$RECAPTCHA_SITE_KEY\"|" front-end/login.html



# === 6. Permissions sur les logs ===

sudo chmod -R 777 ./logs


# === 7. Démarrage des conteneurs ===

docker compose up -d --build


# === 8. Import des dashboards Kibana ===

# On attend que Kibana réponde
sleep 30

curl -X POST http://localhost:5601/api/saved_objects/_import \
     -H "kbn-xsrf: true" \
     --form file=@kibana/exports.ndjson


# === 9. Récap ===

echo ""
echo "Setup terminé."
echo "Secret TOTP : $TOTP_SECRET"
echo "Web         : http://localhost"
echo "Kibana      : http://localhost:5601"
echo "SSH         : ssh -p 2222 admin@localhost"
