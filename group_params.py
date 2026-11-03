"""
group_params.py - the repository group (a 256-bit safe prime P = 2Q + 1) with a primality CERTIFICATE for both numbers.

Nothing here is probabilistic. Q is built bottom-up as a Pocklington chain, every step is a theorem a reader can check
with a few modular exponentiations, and P = 2Q + 1 is proven from Q by one more Pocklington step.

    Pocklington (what is used): if n - 1 = 2*q*R with q prime, 1 <= R <= 2q - 1 (so (2q)^2 > n), and some base a has
        a^(n-1) = 1 (mod n),  gcd(a^((n-1)/2) - 1, n) = 1,  gcd(a^((n-1)/q) - 1, n) = 1,
    then n is prime.  For P = 2Q + 1 the known factor is Q alone: Q^2 > P and  a^(P-1) = 1,  gcd(a^2 - 1, P) = 1.

Derivation (the seed is public; the procedure is fully deterministic):
    tier 0     q0 = 65537 (prime by trial division)
    tier 1..3  q_i = n_{i-1}; for ctr = 0, 1, ...: R = q_i + (hash mod q_i)  (so q <= R <= 2q - 1);
               n = 2*q_i*R + 1; accept the first n that has a Pocklington witness (smallest a >= 2)
    tier 4     q = n_3; R is drawn so that Q = 2*q*R + 1 has exactly 255 bits; accept the first Q that has a witness AND
               whose P = 2Q + 1 has a witness for the factor Q. (cheap Fermat base-2 and small-prime filters come first;
               they only skip candidates, they never accept one: acceptance is the witness test.)
    hash       R-candidate = lo + int(SHA256(seed|tier|ctr|0) || SHA256(seed|tier|ctr|1)) mod (hi - lo + 1),
               tier one byte, ctr eight bytes big-endian.

`verify_certificate(P, Q, cert)` checks everything; `python group_params.py` re-derives and compares.
Educational toy: the group is still a 256-bit subgroup of Z_P*, not a standard curve; unaudited.
"""
import hashlib
import math
import sys

SEED = b"zkrp-toy-group-v2"
TERMINAL = 65537
QBITS = 255

# ---------------------------------------------------------------- fixed output (filled by `python group_params.py --emit`)
P = 0xb8f344dc29e7ea92c63af4fa56718631ea89925a13bcd4bee8880462fddd2903
Q = 0x5c79a26e14f3f549631d7a7d2b38c318f544c92d09de6a5f744402317eee9481
CERT = {"tiers": [(67969, 2), (16538368284, 5), (494959946627345494860, 7)],
        "top": (71694156909245637217911358225110080, 3), "p_witness": 2}


def _stream(tier, ctr, lo, hi):
    pre = SEED + bytes([tier]) + ctr.to_bytes(8, "big")
    x = int.from_bytes(hashlib.sha256(pre + b"\x00").digest() + hashlib.sha256(pre + b"\x01").digest(), "big")
    return lo + x % (hi - lo + 1)


def _witness(n, q, limit=400):
    """Smallest a >= 2 with a^(n-1) = 1, gcd(a^((n-1)/2) - 1, n) = 1 and gcd(a^((n-1)/q) - 1, n) = 1, else None."""
    for a in range(2, limit):
        if pow(a, n - 1, n) == 1 and math.gcd(pow(a, (n - 1) // 2, n) - 1, n) == 1 \
                and math.gcd(pow(a, (n - 1) // q, n) - 1, n) == 1:
            return a
    return None


def _witness_p(p, q, limit=400):
    """For p = 2q + 1: smallest a with a^(p-1) = 1 and gcd(a^2 - 1, p) = 1 (the known factor is q alone)."""
    for a in range(2, limit):
        if pow(a, p - 1, p) == 1 and math.gcd(a * a - 1, p) == 1:
            return a
    return None


_SMALL = [s for s in range(3, 1000, 2) if all(s % d for d in range(3, int(s ** 0.5) + 1, 2))]


def derive(terminal=TERMINAL, qbits=QBITS, ntiers=3):
    """Return (P, Q, cert). cert = {"tiers": [(R, a), ...] bottom-up, "top": (R, a), "p_witness": a}.
    The defaults are the repository group; other sizes exist only so the self-test can build small valid certificates."""
    q, tiers = terminal, []
    for tier in range(1, ntiers + 1):
        ctr = 0
        while True:
            R = _stream(tier, ctr, q, 2 * q - 1)
            n = 2 * q * R + 1
            ctr += 1
            if any(n % s == 0 for s in _SMALL):
                continue
            a = _witness(n, q)
            if a is not None:
                tiers.append((R, a))
                q = n
                break
    lo = ((1 << (qbits - 1)) + 2 * q - 1) // (2 * q)                 # smallest R with 2qR + 1 >= 2^(qbits-1)
    hi = ((1 << qbits) - 2) // (2 * q)                                 # largest R with 2qR + 1 < 2^qbits
    assert 1 <= lo <= hi <= 2 * q - 1
    ctr = 0
    while True:
        R = _stream(ntiers + 1, ctr, lo, hi)
        Qc = 2 * q * R + 1
        Pc = 2 * Qc + 1
        ctr += 1
        if any(Qc % s == 0 or Pc % s == 0 for s in _SMALL):
            continue
        if pow(2, Qc - 1, Qc) != 1 or pow(2, Pc - 1, Pc) != 1:    # cheap filter for a base-2 pseudoprime pair
            # a prime has a^(n-1) = 1 for every base, so base 2 failing means composite; this only skips candidates
            continue
        a = _witness(Qc, q)
        if a is None:
            continue
        ap = _witness_p(Pc, Qc)
        if ap is not None:
            return Pc, Qc, {"tiers": tiers, "top": (R, a), "p_witness": ap}


def _step(q, R, a):
    """One Pocklington step: the prime n = 2qR + 1 if (q, R, a) proves it, else None."""
    n = 2 * q * R + 1
    if not (1 <= R <= 2 * q - 1):                                    # (2q)^2 > n
        return None
    if pow(a, n - 1, n) != 1:
        return None
    if math.gcd(pow(a, (n - 1) // 2, n) - 1, n) != 1:
        return None
    if math.gcd(pow(a, (n - 1) // q, n) - 1, n) != 1:
        return None
    return n


def _p_ok(p, q, a):
    """p = 2q + 1 with q prime: Pocklington with the known factor q alone, so it needs q^2 > p."""
    return p == 2 * q + 1 and q * q > p and pow(a, p - 1, p) == 1 and math.gcd(a * a - 1, p) == 1


def verify_certificate(p, q_top, cert, terminal=TERMINAL, qbits=QBITS):
    """Deterministic. True iff the chain proves q_top prime and the witness proves p = 2 q_top + 1 prime.
    `terminal` and `qbits` exist so the self-test can check small certificates; the repository group uses the defaults."""
    try:
        if type(p) is not int or type(q_top) is not int:
            return False
        if p.bit_length() != qbits + 1 or q_top.bit_length() != qbits:
            return False
        if terminal < 2 or any(terminal % d == 0 for d in range(2, math.isqrt(terminal) + 1)):
            return False                                           # the terminal prime, by trial division
        steps = list(cert["tiers"]) + [cert["top"]]
        if len(steps) > 16:                                        # only a guard against absurd input; any valid chain is a proof
            return False
        q = terminal
        for R, a in steps:
            q = _step(q, R, a)
            if q is None:
                return False
        return q == q_top and _p_ok(p, q_top, cert["p_witness"])
    except Exception:
        return False


def _emit():
    p, q, cert = derive()
    print(f"P = {hex(p)}\nQ = {hex(q)}\nCERT = {cert!r}")


# ============================================================================ self-test
def _mr(n):
    """Deterministic Miller-Rabin for n < 3.3e24 (first 13 prime bases); used only to build small test inputs."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
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


def _selftest():
    import copy
    import random
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    print("1) the repository group")
    check("the stored constants and certificate are filled in", P is not None and Q is not None and CERT is not None)
    check("P = 2Q + 1, 256 and 255 bits", P == 2 * Q + 1 and P.bit_length() == 256 and Q.bit_length() == 255)
    check("the certificate proves Q prime and P prime (deterministic)", verify_certificate(P, Q, CERT))
    check("re-derivation from the public seed gives exactly these constants and this certificate",
          derive() == (P, Q, {"tiers": [tuple(x) for x in CERT["tiers"]], "top": tuple(CERT["top"]), "p_witness": CERT["p_witness"]}))

    print("\n2) tampering with the real certificate")
    c = copy.deepcopy(CERT)
    c["tiers"][0] = (c["tiers"][0][0] + 1, c["tiers"][0][1])
    check("a changed cofactor is rejected", verify_certificate(P, Q, c), False)
    c = copy.deepcopy(CERT)
    c["top"] = (c["top"][0], next(a for a in range(2, 200) if not (pow(a, Q - 1, Q) == 1 and math.gcd(pow(a, (Q - 1) // 2, Q) - 1, Q) == 1)))
    check("a base that is not a witness is rejected", verify_certificate(P, Q, c), False)
    check("a different Q (Q + 2, P + 4) is rejected", verify_certificate(P + 4, Q + 2, CERT), False)
    check("a missing tier is rejected", verify_certificate(P, Q, {"tiers": CERT["tiers"][:2], "top": CERT["top"], "p_witness": CERT["p_witness"]}), False)
    check("malformed input is rejected without an exception", (verify_certificate(P, Q, None), verify_certificate("x", Q, CERT)), (False, False))

    print("\n3) each condition is load-bearing: crafted inputs that satisfy all the others")
    # one Pocklington step: collect tiny cases (q prime, R, a) and see which single condition fails
    cases = {"R": None, "fermat": None, "gcd2": None, "gcdq": None}
    for q in (3, 5, 7, 11, 13, 17, 19, 23):
        for R in range(1, 4 * q):
            n = 2 * q * R + 1
            for a in range(2, 40):
                f = pow(a, n - 1, n) == 1
                g2 = math.gcd(pow(a, (n - 1) // 2, n) - 1, n) == 1
                gq = math.gcd(pow(a, (n - 1) // q, n) - 1, n) == 1
                if R >= 2 * q and f and g2 and gq and cases["R"] is None:
                    cases["R"] = (q, R, a)
                if 1 <= R <= 2 * q - 1:
                    if not f and g2 and gq and cases["fermat"] is None:
                        cases["fermat"] = (q, R, a)
                    if f and not g2 and gq and cases["gcd2"] is None:
                        cases["gcd2"] = (q, R, a)
                    if f and g2 and not gq and cases["gcdq"] is None:
                        cases["gcdq"] = (q, R, a)
    for name, label in (("R", "R >= 2q (every witness condition holds)"), ("fermat", "only the Fermat condition fails"),
                        ("gcd2", "only the gcd for the factor 2 fails"), ("gcdq", "only the gcd for the factor q fails")):
        check(f"step with {label}: case found and rejected", cases[name] is not None and _step(*cases[name]) is None)
    # the final step for P: known factor q alone
    check("P-step with q^2 <= p (q = 2, p = 5, a = 2) is rejected", _p_ok(5, 2, 2), False)
    lone = next(((q, a) for q in range(3, 3000, 2) if _mr(q) and not _mr(2 * q + 1)
                 for a in range(2, 40) if pow(a, 2 * q, 2 * q + 1) == 1 and math.gcd(a * a - 1, 2 * q + 1) != 1), None)
    check("P-step: a composite 2q + 1 with a^(p-1) = 1 but gcd(a^2 - 1, p) != 1 is rejected", lone is not None and not _p_ok(2 * lone[0] + 1, *lone))
    lone = next(((q, a) for q in range(3, 3000, 2) if _mr(q) and not _mr(2 * q + 1)
                 for a in range(2, 40) if pow(a, 2 * q, 2 * q + 1) != 1 and math.gcd(a * a - 1, 2 * q + 1) == 1), None)
    check("P-step: a composite 2q + 1 with gcd ok but a^(p-1) != 1 is rejected", lone is not None and not _p_ok(2 * lone[0] + 1, *lone))
    # a small VALID certificate, then break one structural property at a time
    Ps, Qs, cs = derive(qbits=64, ntiers=1)
    check("a small valid certificate (64-bit Q) verifies with its own size", verify_certificate(Ps, Qs, cs, qbits=64))
    check("... and is rejected under the default 255-bit size (only the bit length differs)", verify_certificate(Ps, Qs, cs), False)
    rng = random.Random(1)
    p2 = next(x for x in (rng.getrandbits(65) | (1 << 64) | 1 for _ in range(100000)) if x != Ps and _mr(x))
    check("a prime p of the right size but p != 2Q + 1 (witness conditions hold) is rejected",
          verify_certificate(p2, Qs, cs, qbits=64), False)
    q2 = next(x for x in (rng.getrandbits(64) | (1 << 63) | 1 for _ in range(100000)) if x != Qs and _mr(x) and _mr(2 * x + 1))
    check("a different safe prime pair (the chain does not end at it) is rejected", verify_certificate(2 * q2 + 1, q2, cs, qbits=64), False)
    check("a composite terminal prime is rejected", verify_certificate(Ps, Qs, cs, terminal=65535, qbits=64), False)
    check("a chain missing its lower tier is rejected", verify_certificate(Ps, Qs, {"tiers": [], "top": cs["top"], "p_witness": cs["p_witness"]}, qbits=64), False)
    Pc, Qc, cc = derive(terminal=65535, qbits=64, ntiers=1)          # every algebraic condition holds with the composite 65535 as the base prime
    check("a chain that starts at a composite terminal 'prime' (65535 = 3 * 5 * 17 * 257) is rejected by the trial-division check",
          verify_certificate(Pc, Qc, cc, terminal=65535, qbits=64), False)
    check("a composite cannot get a witness (Carmichael 561; 111 = 3 * 37)", _witness(561, 3) is None and _witness(111, 5) is None)
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def CERT_AS_DERIVED():
    return {"tiers": [tuple(t) for t in CERT["tiers"]], "top": tuple(CERT["top"]), "p_witness": CERT["p_witness"]}


if __name__ == "__main__":
    if "--emit" in sys.argv:
        _emit()
    else:
        sys.exit(_selftest())
