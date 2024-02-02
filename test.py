
import sympy
import secrets

def is_primitive_root(g, p):
    # Check if g is a primitive root modulo p
    return sympy.is_primitive_root(g, p)

def is_prime(n):
    return sympy.isprime(n)

def generate_large_prime(bits):
    while True:
        candidate = secrets.randbits(bits)
        if is_prime(candidate):
            return candidate
        
def generate_diffie_hellman_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key

def calculate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret


def generate_generator(p):
    # Find a primitive root modulo p
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g

# Select a bit length for the prime number (adjust as needed)
prime_bits = 128

# Find a large prime number for p
p = generate_large_prime(prime_bits)

# Choose a random generator g
g = generate_generator(p)

# Rest of your code remains the same...
# Example usage:
# Generating private keys for Alice and Bob
private_key_Alice = 15
private_key_Bob = 15

# Computing public keys for Alice and Bob
public_key_Alice = generate_diffie_hellman_key(p, g, private_key_Alice)
public_key_Bob = generate_diffie_hellman_key(p, g, private_key_Bob)
print(public_key_Alice)
print(public_key_Bob)
# Exchanging public keys over an insecure channel
# In a real-world scenario, this would be done securely (e.g., through a secure communication channel)
shared_secret_Alice = calculate_shared_secret(public_key_Bob, private_key_Alice, p)
shared_secret_Bob = calculate_shared_secret(public_key_Alice, private_key_Bob, p)

# Both parties now have the same shared secret
print("Shared Secret (Alice):", shared_secret_Alice)
print("Shared Secret (Bob):", shared_secret_Bob)
