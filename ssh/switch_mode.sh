#!/usr/bin/env bash
# Switch SSH auth mode and rebuild the ssh container.
#
# Usage:
#   ./ssh/switch_mode.sh A     # password only
#   ./ssh/switch_mode.sh B     # password + PAM TOTP
#   ./ssh/switch_mode.sh C     # publickey + PAM TOTP (default)

set -e
cd "$(dirname "$0")"

MODE="${1:-}"
case "$MODE" in
  A) CFG=configs/A_password_only.conf  ; PAM=configs/pam_A ; LABEL="password only (no PAM)" ;;
  B) CFG=configs/B_password_pam.conf   ; PAM=configs/pam_B ; LABEL="password + PAM TOTP" ;;
  C) CFG=configs/C_publickey_pam.conf  ; PAM=configs/pam_C ; LABEL="publickey + PAM TOTP" ;;
  *) echo "usage: $0 {A|B|C}" >&2 ; exit 1 ;;
esac

cp "$CFG" sshd_config
cp "$PAM" sshd_pam
echo "[switch_mode] active sshd_config = $CFG  ($LABEL)"
echo "[switch_mode] active sshd_pam    = $PAM"

cd ..

# Reset éventuel verrouillage faillock (sinon le précédent test bloque)
if docker ps --format '{{.Names}}' | grep -q '^ssh$'; then
    docker exec ssh faillock --user admin --reset 2>/dev/null || true
    docker exec ssh faillock --user testuser --reset 2>/dev/null || true
fi

docker-compose up -d --force-recreate --build ssh
echo "[switch_mode] ssh container recreated."

sleep 2
echo
echo "[switch_mode] sshd_config actif :"
docker exec ssh grep -E "^(AuthenticationMethods|PasswordAuthentication|PubkeyAuthentication|UsePAM)" /etc/ssh/sshd_config

echo
echo "[switch_mode] PAM stack actif :"
docker exec ssh grep -vE '^\s*#|^\s*$' /etc/pam.d/sshd
