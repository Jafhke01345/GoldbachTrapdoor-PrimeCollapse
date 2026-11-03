"""
stark_curve.py - the Stark elliptic curve y^2 = x^3 + x + beta over F_p, p = 2^251 + 17 * 2^192 + 1, and a Pedersen
commitment on it:  C = n*G + s*H.

Why this curve: its coordinates live in the same field as the STARK in stark_core.py, so a point addition is a handful
of native field equations inside the circuit (stark_primality.py). The group order Q is prime (about 2^251), so every
point other than infinity generates the whole group.

G is the published generator of the curve (checked below: on the curve, Q*G = infinity, Q prime). H is derived by
hashing to the curve, so nobody knows log_G(H); D is a second hashed point used as the start of the in-circuit
double-and-add (it hides the "point at infinity" corner cases, see stark_primality.py).

Educational toy: pure Python, not constant-time, unaudited. The curve gives roughly 125-bit security against
generic discrete-log attacks; that says nothing about the rest of the repository.

Run `python stark_curve.py` for the self-test.
"""
import hashlib
import sys

P = 2 ** 251 + 17 * 2 ** 192 + 1
ALPHA = 1
BETA = 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89
Q = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f          # prime group order
GX = 0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca
GY = 0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f
G = (GX, GY)


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return type(x) is int and type(y) is int and 0 <= x < P and 0 <= y < P and (y * y - (x ** 3 + ALPHA * x + BETA)) % P == 0


def neg(a):
    return None if a is None else (a[0], (-a[1]) % P)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + ALPHA) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, a):
    k %= Q
    r = None
    for bit in bin(k)[2:] if k else "":
        r = add(r, r)
        if bit == "1":
            r = add(r, a)
    return r


def mul_unreduced(k, a):
    """k*a for a non-negative integer k, WITHOUT reducing k modulo the group order (so it can test the order itself)."""
    if type(k) is not int or isinstance(k, bool) or k < 0:
        raise ValueError("scalar must be a non-negative integer")
    r = None
    while k:
        if k & 1:
            r = add(r, a)
        a = add(a, a)
        k >>= 1
    return r


def _sqrt(a):
    """Tonelli-Shanks; p - 1 = 2^192 * odd."""
    a %= P
    if a == 0:
        return 0
    if pow(a, (P - 1) // 2, P) != 1:
        return None
    s, e = P - 1, 0
    while s % 2 == 0:
        s //= 2
        e += 1
    z = 3                                                   # a quadratic non-residue
    m, c, t, r = e, pow(z, s, P), pow(a, s, P), pow(a, (s + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    return r


def hash_to_point(label):
    """Try-and-increment: the first counter whose x gives a point; y is the even root."""
    ctr = 0
    while True:
        x = int.from_bytes(hashlib.sha256(b"stark_curve|" + label + b"|" + str(ctr).encode()).digest(), "big") % P
        y = _sqrt(x ** 3 + ALPHA * x + BETA)
        if y is not None:
            return (x, y if y % 2 == 0 else P - y)
        ctr += 1


H = hash_to_point(b"H")
D = hash_to_point(b"D")


def commit(n, s):
    """Pedersen commitment C = n*G + s*H (a point; None only if it is the identity)."""
    return add(mul(n, G), mul(s, H))


# ---------------------------------------------------------------- deterministic primality certificates (Pocklington, n - 1 fully factored)
# Theorem: if n - 1 = prod q_i^e_i with every q_i prime, and for each distinct q_i some base a has a^(n-1) = 1 (mod n) and
# gcd(a^((n-1)/q_i) - 1, n) = 1, then n is prime. A factor below 3.3e24 is proven prime by Miller-Rabin with the first 13 prime
# bases (deterministic in that range); a larger factor needs its own entry in the table (its own fully factored f - 1).
_DET_LIMIT = 3317044064679887385961981
_DET_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)


def _det_prime(n):
    if n < 2 or n >= _DET_LIMIT:
        return False
    for p in _DET_BASES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _DET_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _is_int(x):
    return type(x) is int                            # bool and other subclasses are refused


def certify_prime(n, table, _depth=0):
    """True iff `table` proves n prime. table maps a number to the list of prime factors (with repetition) of number - 1."""
    import math
    try:
        if _depth > 8 or not _is_int(n) or n < 2 or type(table) is not dict:
            return False
        if n < _DET_LIMIT and _det_prime(n) and n not in table:
            return True                              # small enough for the deterministic test
        factors = table.get(n)
        if type(factors) not in (list, tuple) or not factors or not all(_is_int(f) and f >= 2 for f in factors):
            return False
        if math.prod(factors) != n - 1:
            return False
        for q in set(factors):
            if not (q == 2 or certify_prime(q, table, _depth + 1)):
                return False
            if not any(pow(a, n - 1, n) == 1 and math.gcd(pow(a, (n - 1) // q, n) - 1, n) == 1 for a in range(2, 300)):
                return False
        return True
    except Exception:
        return False                                 # fail closed on any malformed certificate


# p - 1 = 2^192 * 5 * 7 * 98714381 * 166848103;  Q_C - 1 = 2 * 3 * 1481071 * 74436419 * R, R a 202-bit prime whose own
# R - 1 = 2^4 * 3 * 131797 * 10108547 * 22206313 * 74837449 * 28547348873 * 1803099112058626586861
R202 = 5470365079085120887157193270902448565659295524958143968059153
CERT_TABLE = {
    P: [2] * 192 + [5, 7, 98714381, 166848103],
    Q: [2, 3, 1481071, 74436419, R202],
    R202: [2, 2, 2, 2, 3, 131797, 10108547, 22206313, 74837449, 28547348873, 1803099112058626586861],
}


def _selftest():
    failures = []

    def check(name, ok):
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def is_prime(n):
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    check("p is prime: deterministic Pocklington certificate (p - 1 fully factored)", certify_prime(P, CERT_TABLE))
    check("Q (the curve order) is prime: deterministic certificate, Q - 1 = 2*3*1481071*74436419*R with R a 202-bit prime "
          "that has its own fully factored R - 1", certify_prime(Q, CERT_TABLE))
    check("the 202-bit factor R is itself certified (not just Miller-Rabin)", certify_prime(R202, CERT_TABLE))
    # the certificate is load-bearing: every condition has a crafted input that only that condition rejects
    import math, copy
    check("a wrong number with the same factor list is rejected (Q + 2)", not certify_prime(Q + 2, {Q + 2: CERT_TABLE[Q]}))
    bad = copy.deepcopy(CERT_TABLE)
    bad[Q] = [2, 3, 1481071, 74436419 + 2, R202]
    check("a factor list whose product is not Q - 1 is rejected", not certify_prime(Q, bad))
    bad = copy.deepcopy(CERT_TABLE)
    del bad[R202]
    check("without a certificate for the 202-bit factor the curve order is NOT certified", not certify_prime(Q, bad))
    check("Carmichael 561 with its true factorisation of 560 has no witness for the factor 2", not certify_prime(561, {561: [2, 2, 2, 2, 5, 7]}))
    comp = next(((n, m) for n in range(9, 2000, 2) if not _det_prime(n) and (n - 1) % 2 == 0
                 for m in [(n - 1) // 2] if not _det_prime(m) and
                 all(any(pow(a, n - 1, n) == 1 and math.gcd(pow(a, (n - 1) // q, n) - 1, n) == 1 for a in range(2, 300)) for q in (2, m))), None)
    check("a composite 'factor' m with a passing witness is rejected because m is not prime", comp is not None and not certify_prime(comp[0], {comp[0]: [2, comp[1]]}))
    def _fact(m):
        out, p = [], 2
        while p * p <= m:
            while m % p == 0:
                out.append(p)
                m //= p
            p += 1
        return out + ([m] if m > 1 else [])

    def _gcd_only(n_, q_):
        return any(math.gcd(pow(a, (n_ - 1) // q_, n_) - 1, n_) == 1 for a in range(2, 300))

    fer = next((n_ for n_ in range(9, 5000, 2) if not _det_prime(n_)
                and all(_gcd_only(n_, q_) for q_ in set(_fact(n_ - 1)))), None)
    check("a composite n whose factors of n - 1 all pass the gcd condition is rejected only by the Fermat condition",
          fer is not None and not certify_prime(fer, {fer: _fact(fer - 1)}))
    mal = (certify_prime(Q, None), certify_prime(Q, []), certify_prime(Q, {Q: None}), certify_prime(Q, {Q: "23"}),
           certify_prime(Q, {Q: [2, 3, True]}), certify_prime(Q, {Q: [2, 3.0]}), certify_prime(Q, {Q: [2, 3, -5]}),
           certify_prime(Q, {Q: []}), certify_prime(True, {}), certify_prime("97", {}), certify_prime(None, {}),
           certify_prime(97, {97: [2, 2, 2, 2, 2, 3, 0]}))
    check("malformed tables, factor lists and numbers are rejected without an exception", not any(mal))
    check("a boolean is not accepted as a factor or as the number", not certify_prime(3, {3: [True, 2]}) and not certify_prime(True, {}))
    check("a prime n whose factor list is incomplete (97: [2, 3], product 6 != 96) is rejected", not certify_prime(97, {97: [2, 3]}))
    check("the deterministic test refuses numbers above its proven range (Q)", not _det_prime(Q))
    check("the deterministic test rejects strong pseudoprimes to the first bases (1373653 to bases 2, 3; 3215031751 to 2, 3, 5, 7)",
          not _det_prime(1373653) and not _det_prime(3215031751))
    check("a number with no table entry and too large for the deterministic test is rejected", not certify_prime(Q, {}))
    check("a prime below the deterministic limit needs no entry (97)", certify_prime(97, {}))
    check("the Hasse interval holds: |Q - (p + 1)| <= 2 sqrt(p)", abs(Q - (P + 1)) ** 2 <= 4 * P)
    # mul() reduces its scalar modulo Q, so mul(Q, G) would be the identity whatever Q is; the order is tested unreduced
    check("G is on the curve, G is not the identity, and Q*G is the identity (unreduced scalar)",
          on_curve(G) and G is not None and mul_unreduced(Q, G) is None)
    check("the unreduced test is not vacuous: (Q - 1)*G is not the identity and Q + 1 gives G back",
          mul_unreduced(Q - 1, G) is not None and mul_unreduced(Q + 1, G) == G)
    _Q0 = Q
    globals()["Q"] = _Q0 + 1                         # if mul_unreduced consulted Q, this would change its answer
    try:
        independent = mul_unreduced(_Q0 + 1, G) == G and mul_unreduced(_Q0, G) is None
    finally:
        globals()["Q"] = _Q0
    check("mul_unreduced does not depend on the module's group order", independent)
    check("mul reduces its scalar (mul(Q, G) is the identity by construction), unlike mul_unreduced",
          mul(Q, G) is None and mul(Q + 1, G) == G)
    check("H and D are on the curve and different from each other and from G",
          on_curve(H) and on_curve(D) and len({G, H, D}) == 3)
    check("the group law is consistent: (a + b)*G = a*G + b*G", mul(12345 + 67890, G) == add(mul(12345, G), mul(67890, G)))
    check("negation: P + (-P) is the identity", add(H, neg(H)) is None)
    check("doubling agrees with addition", add(H, H) == mul(2, H))
    n, s = 0x1234567890ABCDEF, 0xFEDCBA0987654321FEDCBA0987654321
    check("Pedersen is homomorphic", add(commit(n, s), commit(5, 7)) == commit(n + 5, s + 7))
    check("a point off the curve is rejected by on_curve", not on_curve((GX, (GY + 1) % P)))
    check("_sqrt agrees with squaring", all(_sqrt(x * x % P) in (x, P - x) for x in (2, 12345, P - 3)))
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
