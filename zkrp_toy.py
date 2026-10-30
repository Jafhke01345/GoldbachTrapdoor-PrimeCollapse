"""
zkrp_toy.py - educational zero-knowledge range-proof prototype (pure Python, no dependencies).

Statement proved, for a PUBLIC integer c:
    "I know hidden integers a and b with a + b = 2c and 0 <= a <= c <= b."

Building blocks
  * Pedersen commitments   C = g^m * h^r      (perfectly hiding, computationally binding)
  * Schnorr proof of knowledge (Fiat-Shamir)  that Ca * Cb = g^(2c) * h^s
  * Bit-decomposition range proofs with Schnorr OR-proofs, applied to `a` and to `c - a`.
    Two range proofs are needed: `a` in [0, 2^N) stops negative / wrapped values, and
    `c - a` in [0, 2^N) gives a <= c <= b.

NOT included: any proof that a and b are prime (see PRIMALITY.md).
NOT production crypto: 256-bit toy group, O(N) proof size, not constant-time, unaudited.
The group parameters are regenerated on every import (fine for a toy, not for deployment).
"""
import hashlib
import secrets

# ---------------------------------------------------------------- number theory
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_safe_prime(bits):
    """Return (p, q) with p = 2q + 1, both prime. Squares mod p form the order-q subgroup."""
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        p = 2 * q + 1
        if any(q % s == 0 or p % s == 0 for s in _SMALL_PRIMES):
            continue
        if is_probable_prime(q) and is_probable_prime(p):
            return p, q


def hash_to_subgroup(label, p):
    """Nothing-up-my-sleeve subgroup element: nobody knows log_g(h)."""
    ctr = 0
    while True:
        digest = b"".join(
            hashlib.sha256(label + ctr.to_bytes(4, "big") + i.to_bytes(2, "big")).digest()
            for i in range((p.bit_length() + 255) // 256 + 1)
        )
        x = pow(int.from_bytes(digest, "big") % p, 2, p)
        if x not in (0, 1):
            return x
        ctr += 1


# ---------------------------------------------------------------- public parameters
P, Q = gen_safe_prime(256)
G = hash_to_subgroup(b"zkrp-toy-g", P)
H = hash_to_subgroup(b"zkrp-toy-h", P)
G_INV = pow(G, -1, P)
N_BITS = 32                                   # values are proven to lie in [0, 2^32)
assert 2 ** (N_BITS + 3) < Q                  # a + b = 2c cannot wrap around mod q


def commit(m, r):
    return pow(G, m % Q, P) * pow(H, r % Q, P) % P


def challenge(*items):
    data = b"|".join(str(i).encode() for i in (P, G, H) + items)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


# ---------------------------------------------------------------- bit proof (Schnorr OR)
def or_prove(B, bit, r, ctx):
    """Prove B = h^r (bit 0) OR B/g = h^r (bit 1) without revealing which."""
    Y = [B, B * G_INV % P]
    real, sim = bit, 1 - bit
    e_sim, z_sim = secrets.randbelow(Q), secrets.randbelow(Q)
    T = [None, None]
    T[sim] = pow(H, z_sim, P) * pow(Y[sim], (-e_sim) % Q, P) % P      # simulated branch
    t = secrets.randbelow(Q)
    T[real] = pow(H, t, P)                                            # real branch
    e = challenge(ctx, B, T[0], T[1])
    e_real = (e - e_sim) % Q
    z_real = (t + e_real * r) % Q
    es, zs = [None, None], [None, None]
    es[real], es[sim] = e_real, e_sim
    zs[real], zs[sim] = z_real, z_sim
    return (T[0], T[1], es[0], es[1], zs[0], zs[1])


def or_verify(B, proof, ctx):
    T0, T1, e0, e1, z0, z1 = proof
    Y0, Y1 = B, B * G_INV % P
    if (e0 + e1) % Q != challenge(ctx, B, T0, T1):
        return False
    return (pow(H, z0, P) == T0 * pow(Y0, e0, P) % P and
            pow(H, z1, P) == T1 * pow(Y1, e1, P) % P)


# ---------------------------------------------------------------- range proof
def range_prove(m, r, n, ctx, _cheat=False):
    """Prove C = g^m h^r has 0 <= m < 2^n. `_cheat` is a TEST HOOK that skips the honesty check."""
    if not _cheat and not (0 <= m < 2 ** n):
        raise ValueError(f"value out of range for {n} bits")
    low = m % (2 ** n) if _cheat else m
    bits = [(low >> i) & 1 for i in range(n)]
    rs = [secrets.randbelow(Q) for _ in range(n)]
    rs[0] = (r - sum(rs[i] * (1 << i) for i in range(1, n))) % Q      # sum r_i 2^i == r
    Bs = [commit(bits[i], rs[i]) for i in range(n)]
    proofs = [or_prove(Bs[i], bits[i], rs[i], f"{ctx}:{i}") for i in range(n)]
    return Bs, proofs


def range_verify(C, rp, n, ctx):
    Bs, proofs = rp
    if len(Bs) != n or len(proofs) != n:
        return False
    recombined = 1
    for i, B in enumerate(Bs):
        recombined = recombined * pow(B, 1 << i, P) % P               # prod B_i^(2^i)
    if recombined != C:
        return False
    return all(or_verify(Bs[i], proofs[i], f"{ctx}:{i}") for i in range(n))


# ---------------------------------------------------------------- full statement
def prove(a, b, _cheat=False):
    """Return the public transcript. `_cheat` is a TEST HOOK used by benchmark.py."""
    if (a + b) % 2:
        raise ValueError("a + b must be even so that c is an integer")
    c = (a + b) // 2
    x = c - a                                                         # = (b - a) / 2
    ra, rb = secrets.randbelow(Q), secrets.randbelow(Q)
    Ca, Cb = commit(a, ra), commit(b, rb)
    rx = (-ra) % Q                                                    # C_x = g^c / C_a = g^x h^(-ra)

    rp_a = range_prove(a, ra, N_BITS, "a", _cheat)
    rp_x = range_prove(x, rx, N_BITS, "x", _cheat)

    s = (ra + rb) % Q
    D = Ca * Cb * pow(G, (-2 * c) % Q, P) % P                         # = h^s iff a + b == 2c
    t = secrets.randbelow(Q)
    T = pow(H, t, P)
    e = challenge(c, Ca, Cb, T)
    z = (t + e * s) % Q
    return {"c": c, "Ca": Ca, "Cb": Cb, "T": T, "z": z, "rp_a": rp_a, "rp_x": rp_x}


def verify(pub, claimed_c=None):
    """Verifier sees only the public transcript (and optionally the c it expects).
    Fails closed: a malformed transcript yields False, never an exception."""
    try:
        return _verify(pub, claimed_c)
    except Exception:
        return False


def _verify(pub, claimed_c):
    c = pub["c"] if claimed_c is None else claimed_c
    # Integer-level guarantee. The proofs only bind c modulo Q, so c itself must be a plain integer
    # in [0, 2^(N_BITS+1)): then c = a + x EXACTLY over the integers (a, x < 2^N_BITS < Q), hence
    # b = 2c - a = a + 2x and a <= c <= b hold over the integers, not just mod Q. Without this check
    # a transcript claiming c + Q (same residue) would verify.
    if type(c) is not int or not (0 <= c < 2 ** (N_BITS + 1)):
        return False
    Ca, Cb = pub["Ca"], pub["Cb"]
    Cx = pow(G, c % Q, P) * pow(Ca, -1, P) % P
    D = Ca * Cb * pow(G, (-2 * c) % Q, P) % P
    e = challenge(c, Ca, Cb, pub["T"])
    sum_ok = pow(H, pub["z"], P) == pub["T"] * pow(D, e, P) % P
    return (sum_ok
            and range_verify(Ca, pub["rp_a"], N_BITS, "a")
            and range_verify(Cx, pub["rp_x"], N_BITS, "x"))


def proof_size_bytes(pub):
    """Approximate serialized size: group elements and scalars at their natural byte widths."""
    ge, sc = (P.bit_length() + 7) // 8, (Q.bit_length() + 7) // 8
    per_bit = 3 * ge + 4 * sc                                         # B_i, T0, T1 | e0, e1, z0, z1
    return 3 * ge + sc + 2 * N_BITS * per_bit                         # Ca, Cb, T | z | two range proofs
