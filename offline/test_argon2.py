from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

# Générer un hash
password = "SecurePass123!"
hash = ph.hash(password)
print(f"Hash généré :\n{hash}\n")

# Vérifier bon mot de passe
try:
    ph.verify(hash, "SecurePass123!")
    print("✓ Bon mot de passe : accepté")
except VerifyMismatchError:
    print("✗ Erreur")

# Vérifier mauvais mot de passe
try:
    ph.verify(hash, "mauvaismdp")
    print("✗ Mauvais mot de passe : accepté (PROBLÈME)")
except VerifyMismatchError:
    print("✓ Mauvais mot de passe : rejeté")

# Montrer que deux hash du même mdp sont différents (sel aléatoire)
hash2 = ph.hash(password)
print(f"\nHash 1 : {hash[:30]}...")
print(f"Hash 2 : {hash2[:30]}...")
print(f"Identiques ? {hash == hash2}")  # False → preuve du sel
