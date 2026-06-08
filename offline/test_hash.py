from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import time

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

# Hash du mot de passe "victime"
target_hash = ph.hash("password123")

wordlist = ["admin", "123456", "azerty", "password", "password123", "letmein"]

print("=== Tentative de crack Argon2id ===\n")
for word in wordlist:
    start = time.time()
    try:
        ph.verify(target_hash, word)
        print(f"[+] CRACKÉ : {word} ({time.time()-start:.3f}s)")
        break
    except VerifyMismatchError:
        print(f"[-] {word:20s} → raté ({time.time()-start:.3f}s)")
        
import hashlib
target_md5 = hashlib.md5(b"password123").hexdigest()

print("\n=== Tentative de crack MD5 (comparaison) ===\n")
for word in wordlist:
    start = time.time()
    if hashlib.md5(word.encode()).hexdigest() == target_md5:
        print(f"[+] CRACKÉ : {word} ({time.time()-start:.6f}s)")
        break
    else:
        print(f"[-] {word:20s} → raté ({time.time()-start:.6f}s)")
