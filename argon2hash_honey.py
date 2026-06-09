from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2
)

honey_passwords = {
    "backup_admin": "BackupAdmin2024!",
    "audit_service": "AuditService2024!",
    "old_admin": "OldAdmin2024!"
}

for username, password in honey_passwords.items():
    print(username)
    print(ph.hash(password))
    print()
PY
