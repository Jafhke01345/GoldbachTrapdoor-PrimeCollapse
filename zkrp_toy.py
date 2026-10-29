import secrets

def zkrp_toy(a, b, p):
    """
    Zero-Knowledge Range Proof (ZKRP) Toy Implementation
    PrimeCollapse: Inverse-Sum Blinding Protocol
    """
    # Public parameters derived from inputs
    sum_val = a + b
    median_c = sum_val // 2

    # Secret scalar r must be coprime to p; since p is prime, any 1 < r < p works.
    r = secrets.randbelow(p - 2) + 2
    
    try:
        # Blinding key k = r * S^-1 mod p
        k = (r * pow(sum_val, -1, p)) % p
    except ValueError:
        raise ValueError("Sum not invertible modulo p")

    # Blinded coordinates
    blinded_a = (a * k) % p
    blinded_b = (b * k) % p
    
    # Verification values
    v_sum = (blinded_a + blinded_b) % p
    v_med = (2 * median_c * k * pow(r, -1, p)) % p
    
    return {
        "blinded_a": blinded_a,
        "blinded_b": blinded_b,
        "v_sum": v_sum,
        "v_med": v_med
    }

if __name__ == "__main__":
    # Use a standard large prime (Mersenne prime 2^521-1) for toy testing
    P = 2**521 - 1
    A = secrets.randbits(512)
    B = secrets.randbits(512)
    
    try:
        res = zkrp_toy(A, B, P)
        print("ZKRP proof generated.")
        print(f"Blinded A: {hex(res['blinded_a'])}")
        print(f"Blinded B: {hex(res['blinded_b'])}")
    except Exception as e:
        print(f"Error: {e}")
