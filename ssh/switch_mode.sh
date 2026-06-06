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
  A) CFG=configs/A_password_only.conf  ; LABEL="password only (no PAM)" ;;
  B) CFG=configs/B_password_pam.conf   ; LABEL="password + PAM TOTP" ;;
  C) CFG=configs/C_publickey_pam.conf  ; LABEL="publickey + PAM TOTP" ;;
  *) echo "usage: $0 {A|B|C}" >&2 ; exit 1 ;;
esac

cp "$CFG" sshd_config
echo "[switch_mode] active config = $CFG  ($LABEL)"

cd ..
docker compose up -d --force-recreate --build ssh
echo "[switch_mode] ssh container recreated."

sleep 2
echo "[switch_mode] active sshd_config inside container:"
docker exec ssh grep -E "^(AuthenticationMethods|PasswordAuthentication|PubkeyAuthentication|UsePAM)" /etc/ssh/sshd_config
