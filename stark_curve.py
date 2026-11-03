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

    check("p and Q are prime", is_prime(P) and is_prime(Q))
    check("the Hasse interval holds: |Q - (p + 1)| <= 2 sqrt(p)", abs(Q - (P + 1)) ** 2 <= 4 * P)
    check("G is on the curve and Q*G is the identity", on_curve(G) and mul(Q, G) is None)
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
