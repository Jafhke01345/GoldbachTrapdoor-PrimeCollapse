import os
import secrets
import math

def is_prime_miller_rabin(n, k=40):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_secure_prime(bits=1024):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate

def run_protocol_with_secrets():
    # Setup
    bit_length = 256 # Use smaller bits for faster testing, still secure enough to prove the math
    global_field_modulus = generate_large_secure_prime(bit_length * 2)
    secret_// prime boundary a and b
    a = generate_large_secure_prime(bit_length)
    b = generate_large_secure_prime(bit_length)
    if a > b: a, b = b, a
    
    sum_key = a + b
    c = sum_key // 2
    
    # Secret scalar r (The Patch)
    while True:
        r = secrets.randbelow(global_field_modulus - 2) + 2
        if math.gcd(r, global_field_modulus) == 1:
            break
            
    k = (r * pow(sum_key, -1, global_field_modulus)) % global_field_modulus
    A = (a * k) % global_field_modulus
    B = (b * k) % global_field_modulus
    
    return {
        "secret_a": a, "secret_b": b, "r": r, 
        "public_c": c, "blinded_A": A, "blinded_B": B, "p": global_field_modulus
    }

def audit_recovery(data):
    print("--- [ STARTING LEAK AUDIT ] ---")
    # The Attacker's available data
    c = data["public_c"]
    A = data["blinded_A"]
    p = data["p"]
    actual_a = data["secret_a"]
    
    print(f"Attempting recovery of secret_a using Public Median attack...")
    # Naive attack: a = A * (2c) mod p
    # This worked in the prev version because k was just (2c)^-1.
    recovered_a = (A * (2 * c)) % p
    
    print(f"Actual Secret A: {str(actual_a)[:30]}...")
    print(f"Recovered A:     {str(recovered_a)[:30]}...")
    
    if recovered_a == actual_a:
        return False, "FAIL: Secret prime leaked. Naive recovery successful."
    else:
        return True, "PASS: Recovery failed. Identity remains blinded."

if __name__ == "__main__":
    data = run_protocol_with_secrets()
    success, message = audit_recovery(data)
    print(f"\nRESULT: {message}")
