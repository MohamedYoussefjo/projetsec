import hashlib, crypt, time

password = "SecurePass123!"

# MD5 (MAUVAIS - crackable en secondes)
md5 = hashlib.md5(password.encode()).hexdigest()

# SHA-256 sans sel (MAUVAIS)
sha256 = hashlib.sha256(password.encode()).hexdigest()

# bcrypt (bien, mais vieillissant)
import bcrypt
bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Argon2id (RECOMMANDÉ - résistant GPU/ASIC)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
argon2_hash = ph.hash(password)
