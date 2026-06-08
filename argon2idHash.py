from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2
)

print(ph.hash("SecurePass123!"))
