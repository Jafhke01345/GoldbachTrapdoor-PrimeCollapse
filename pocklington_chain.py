"""
Toy: provable primes via a Pocklington chain (Pratt-style certificate, but only HALF of n-1
needs to be factored, which is what makes it practical).

Pocklington's criterion: let n = F*R + 1 with F > sqrt(n) and F fully factored.
If there is an `a` with
    a^(n-1) == 1 (mod n)   and   gcd(a^((n-1)/f) - 1, n) == 1   for every prime f | F,
then n is prime.

Here F = 2*q with q a smaller PROVEN prime and R < q, so F^2 > n.
Each level roughly doubles the bit length: 17 -> 33 -> 65 -> 129 -> 257 -> ...

IMPORTANT: this certificate is PUBLIC (it reveals n). It is the witness a ZK circuit would
check, not a zero-knowledge proof by itself. Not constant-time; educational only.
"""
import secrets
import time
from math import gcd

BASE_BITS = 20


# ------------------------------------------------------------------ base case
def small_is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gen_small_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if small_is_prime(n):
            return n


# ------------------------------------------------------------------ prover side
def find_witness(n, q):
    """Search a for the Pocklington conditions with F = 2q; None if n is composite/unlucky."""
    for a in range(2, 60):
        if pow(a, n - 1, n) != 1:
            return None                      # Fermat failure => n is certainly composite
        if all(gcd(pow(a, (n - 1) // f, n) - 1, n) == 1 for f in (2, q)):
            return a
    return None


def gen_provable_prime(bits):
    """Return (n, chain). chain[0] is a small base prime; each later entry certifies one level."""
    if bits <= BASE_BITS:
        n = gen_small_prime(bits)
        return n, [{"n": n}]
    q, chain = gen_provable_prime(bits // 2 + 1)
    r_bits = max(2, bits - q.bit_length() - 1)          # keeps R < q
    while True:
        R = secrets.randbits(r_bits) | (1 << (r_bits - 1))
        n = 2 * q * R + 1
        a = find_witness(n, q)
        if a is not None:
            chain.append({"n": n, "R": R, "a": a})
            return n, chain


# ------------------------------------------------------------------ verifier side
def verify_chain(chain):
    """Return the certified prime at the top of the chain, or None if any step fails."""
    base = chain[0]["n"]
    if base >= 2 ** (BASE_BITS + 1) or not small_is_prime(base):
        return None
    q = base
    for step in chain[1:]:
        n, R, a = step["n"], step["R"], step["a"]
        if n != 2 * q * R + 1:
            return None                                  # chain link broken
        if not (4 * q * q > n):
            return None                                  # need F = 2q > sqrt(n)
        if pow(a, n - 1, n) != 1:
            return None                                  # Fermat condition
        for f in (2, q):                                 # prime factors of F
            if gcd(pow(a, (n - 1) // f, n) - 1, n) != 1:
                return None
        q = n
    return q


# ------------------------------------------------------------------ demo
def main():
    for bits in (128, 256, 512, 1024):
        t0 = time.perf_counter()
        n, chain = gen_provable_prime(bits)
        t1 = time.perf_counter()
        top = verify_chain(chain)
        t2 = time.perf_counter()
        sizes = " -> ".join(str(s["n"].bit_length()) for s in chain)
        print(f"{bits:>4}-bit: certified={top == n} | levels: {sizes}")
        print(f"        generate {t1 - t0:.2f}s, verify {t2 - t1:.3f}s")

    print("\nTamper tests on a 256-bit chain")
    n, chain = gen_provable_prime(256)
    bad = [dict(s) for s in chain]
    bad[-1]["R"] += 1
    print("  R changed           ->", verify_chain(bad))
    bad = [dict(s) for s in chain]
    bad[-1]["n"] += 2
    print("  n changed           ->", verify_chain(bad))
    bad = [dict(s) for s in chain]
    bad[1]["a"] = 1
    print("  witness a = 1       ->", verify_chain(bad))
    # try to certify a composite of the right shape n = 2*q*R + 1 with a guessed witness
    q = chain[-2]["n"]
    R = chain[-1]["R"]
    while True:
        R += 1
        cand = 2 * q * R + 1
        if pow(2, cand - 1, cand) != 1:                  # composite candidate
            break
    bad = [dict(s) for s in chain]
    bad[-1] = {"n": cand, "R": R, "a": 2}
    print("  composite candidate ->", verify_chain(bad))
    print("  untouched chain     ->", verify_chain(chain) == n)


if __name__ == "__main__":
    main()
