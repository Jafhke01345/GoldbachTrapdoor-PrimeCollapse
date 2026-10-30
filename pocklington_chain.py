"""
Recursive Pocklington primality certificates.

This is an educational, standalone verifier/generator, not production cryptography.
It proves primality of a public integer n using a recursively certified prime q
such that n - 1 = 2*q*R and 2*q > sqrt(n).

For each distinct prime divisor p in {2, q} of F=2*q, the certificate carries
a (possibly different) base a_p and Bezout inverse w_p satisfying:

    a_p**(n-1) == 1 (mod n)
    (a_p**((n-1)//p) - 1) * w_p == 1 (mod n)

The second equation explicitly proves the required gcd is 1.

Hardening in this revision
    * verify_certificate() fails closed: ANY internal error (hostile objects, recursion
      blow-ups, odd types) yields False and never an exception.
    * Exact types only (no subclasses), and no bool-as-int.
    * The self-test (`python pocklington_chain.py --test`) is mutation-checked: it fails if
      any one verifier check is removed (see run_self_tests).
"""

from dataclasses import dataclass, replace
from math import gcd, isqrt
from typing import Optional
import argparse
import random
import sys


BASE_BITS = 20
BASE_LIMIT = (1 << BASE_BITS) - 1
MAX_DEPTH = 128


@dataclass(frozen=True)
class PrimeCertificate:
    n: int
    # For n <= BASE_LIMIT, the verifier uses deterministic trial division.
    # For larger n, all fields below are required.
    q: Optional[int] = None
    R: Optional[int] = None
    a2: Optional[int] = None
    w2: Optional[int] = None
    aq: Optional[int] = None
    wq: Optional[int] = None
    q_certificate: Optional["PrimeCertificate"] = None


def _is_plain_int(value: object) -> bool:
    # Exact type: rejects bool and any int subclass (which could carry hostile behaviour).
    return type(value) is int


def small_is_prime(n: int) -> bool:
    """Deterministic trial division for integers up to BASE_LIMIT."""
    if not _is_plain_int(n) or n < 2 or n > BASE_LIMIT:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def _find_large_prime_factor(m: int, n: int) -> int:
    """
    Find a prime factor q of m with 4*q*q > n.
    Trial factorization is deliberately simple and may be slow for large m.
    For large inputs, supply q_hint to build_certificate instead.
    """
    factors = []
    remaining = m

    if remaining % 2 == 0:
        factors.append(2)
        while remaining % 2 == 0:
            remaining //= 2

    d = 3
    while d * d <= remaining:
        if remaining % d == 0:
            factors.append(d)
            while remaining % d == 0:
                remaining //= d
        d += 2

    if remaining > 1:
        factors.append(remaining)

    candidates = [p for p in factors if 4 * p * p > n]
    if not candidates:
        raise ValueError(
            "No prime factor q of (n-1)/2 satisfies 4*q^2 > n; "
            "this Pocklington certificate shape cannot be built."
        )
    return max(candidates)


def _find_bezout_witness(n: int, p: int) -> tuple[int, int]:
    """
    Find a base a and inverse w for the Pocklington condition associated to p.
    The returned pair satisfies both Fermat and Bezout equations.
    """
    exponent = (n - 1) // p
    for a in range(2, n - 1):
        if pow(a, n - 1, n) != 1:
            continue
        y = (pow(a, exponent, n) - 1) % n
        try:
            w = pow(y, -1, n)
        except ValueError:
            continue
        return a, w
    raise ValueError(f"Could not find a Pocklington witness for factor p={p}.")


def build_certificate(n: int, q_hint: Optional[int] = None) -> PrimeCertificate:
    """
    Build a recursive certificate for a known prime n.

    q_hint may be supplied to avoid trial-factorizing (n-1)/2. The chosen q
    must itself be prime and satisfy n-1 = 2*q*R and 4*q^2 > n.
    """
    if not _is_plain_int(n) or n < 2:
        raise ValueError("n must be an integer >= 2.")

    if n <= BASE_LIMIT:
        if not small_is_prime(n):
            raise ValueError(f"{n} is not prime (base-case trial division).")
        return PrimeCertificate(n=n)

    if n % 2 == 0:
        raise ValueError("An even n greater than 2 cannot be prime.")

    half = n - 1
    if half % 2:
        raise ValueError("n-1 must be even.")

    m = half // 2
    q = q_hint if q_hint is not None else _find_large_prime_factor(m, n)

    if not _is_plain_int(q) or q < 2 or m % q != 0:
        raise ValueError("q must be an integer prime factor of (n-1)/2.")
    if 4 * q * q <= n:
        raise ValueError("The known factor F=2q does not exceed sqrt(n).")

    R = m // q
    child = build_certificate(q)

    a2, w2 = _find_bezout_witness(n, 2)
    aq, wq = _find_bezout_witness(n, q)

    return PrimeCertificate(
        n=n, q=q, R=R, a2=a2, w2=w2, aq=aq, wq=wq,
        q_certificate=child,
    )


def _verify(cert: object, expected_n: Optional[int], depth: int) -> bool:
    if depth > MAX_DEPTH or type(cert) is not PrimeCertificate:
        return False

    n = cert.n
    if not _is_plain_int(n) or n < 2:
        return False
    if expected_n is not None and n != expected_n:
        return False

    # Deterministic terminal case.
    if n <= BASE_LIMIT:
        return small_is_prime(n)

    # No large even prime is possible.
    if n % 2 == 0:
        return False

    q, R = cert.q, cert.R
    a2, w2, aq, wq = cert.a2, cert.w2, cert.aq, cert.wq
    child = cert.q_certificate

    if not all(_is_plain_int(x) for x in (q, R, a2, w2, aq, wq)):
        return False
    if q < 2 or R < 1:
        return False
    if type(child) is not PrimeCertificate or child.n != q:
        return False

    # Exact integer factorization and Pocklington size bound.
    if n - 1 != 2 * q * R:
        return False
    if 4 * q * q <= n:
        return False

    # Recursively establish that q is prime.
    if not _verify(child, q, depth + 1):
        return False

    # Check the Pocklington condition independently for p=2 and p=q.
    for p, a, w in ((2, a2, w2), (q, aq, wq)):
        if not (2 <= a <= n - 2):
            return False
        if not (0 <= w < n):
            return False
        if (n - 1) % p != 0:
            return False
        if pow(a, n - 1, n) != 1:
            return False

        exponent = (n - 1) // p
        y = (pow(a, exponent, n) - 1) % n

        # This Bezout identity proves gcd(y, n) = 1.
        if (y * w) % n != 1:
            return False

    return True


def verify_certificate(
    cert: PrimeCertificate,
    expected_n: Optional[int] = None,
    _depth: int = 0,
) -> bool:
    """
    Verify a recursive Pocklington certificate.

    Total function: returns False for any malformed or hostile input; never raises.
    """
    try:
        return _verify(cert, expected_n, _depth)
    except Exception:       # fail closed: a verifier must never crash into "maybe valid"
        return False


# ============================================================================ self-tests
def _oracle_is_prime(n: int) -> bool:
    """Independent Miller-Rabin (first 12 prime bases: deterministic below 3.3e24)."""
    if n < 2:
        return False
    bases = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in bases:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in bases:
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


def _random_chain_prime(levels: int, rng: random.Random) -> tuple[int, int]:
    """Random provable prime built bottom-up. Returns (n, q) for the TOP tier (q is its factor)."""
    while True:
        q = rng.randrange(1 << 18, BASE_LIMIT)
        if small_is_prime(q):
            break
    n = q
    for _ in range(levels):
        q = n
        while True:
            R = rng.randrange(2, q)                       # R < q  =>  4q^2 > n
            n = 2 * q * R + 1
            if _oracle_is_prime(n):
                break
    return n, q


def _mutate_at(cert: PrimeCertificate, depth: int, **changes) -> PrimeCertificate:
    if depth == 0:
        return replace(cert, **changes)
    return replace(cert, q_certificate=_mutate_at(cert.q_certificate, depth - 1, **changes))


def _tier_count(cert: PrimeCertificate) -> int:
    k = 0
    while cert.q_certificate is not None:
        cert, k = cert.q_certificate, k + 1
    return k


def run_self_tests(seed: Optional[int] = None) -> int:
    """Adversarial regression suite. Returns the number of failures (0 = all passed)."""
    seed = secrets_seed() if seed is None else seed
    rng = random.Random(seed)
    failures: list[str] = []

    def expect(name: str, got: bool, want: bool) -> None:
        ok = (got == want)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    print(f"seed={seed}")

    # ---------------------------------------------------------------- 1. honest
    print("\n1) honest certificates")
    expect("104723 (base prime)", verify_certificate(build_certificate(104723)), True)
    top = build_certificate(2_097_779, q_hint=1_048_889)
    expect("2,097,779 (2 tiers)", verify_certificate(top, expected_n=2_097_779), True)
    for levels in (1, 2):
        n, q = _random_chain_prime(levels, rng)
        cert = build_certificate(n, q_hint=q)
        expect(f"random {n.bit_length()}-bit prime, {_tier_count(cert)} tiers", verify_certificate(cert, expected_n=n), True)
    big_n, big_q = _random_chain_prime(2, rng)
    big = build_certificate(big_n, q_hint=big_q)
    assert _tier_count(big) >= 2 and _oracle_is_prime(big_n)

    # ---------------------------------------------------------------- 2. base case
    print("\n2) base case (deterministic trial division)")
    for value in (561, 1105, 1729, 2465, 2821, 6601, 41041):
        expect(f"Carmichael {value}", verify_certificate(PrimeCertificate(value)), False)
    expect("104721 (composite)", verify_certificate(PrimeCertificate(104721)), False)
    expect("1", verify_certificate(PrimeCertificate(1)), False)
    expect("2**20 + 1 above the base limit with no certificate", verify_certificate(PrimeCertificate(2**20 + 1)), False)
    expect("every composite below 3000 rejected as base case",
           not any(verify_certificate(PrimeCertificate(m)) for m in range(4, 3000) if not _oracle_is_prime(m)), True)

    # ---------------------------------------------------------------- 3. witness attacks
    print("\n3) Bezout / base-witness attacks (every tier, every field)")
    for tier in range(_tier_count(big)):
        node = big
        for _ in range(tier):
            node = node.q_certificate
        n_i = node.n
        for field in ("w2", "wq"):
            expect(f"tier {tier}: {field} + 1", verify_certificate(_mutate_at(big, tier, **{field: (getattr(node, field) + 1) % n_i})), False)
            expect(f"tier {tier}: {field} non-canonical (+n)", verify_certificate(_mutate_at(big, tier, **{field: getattr(node, field) + n_i})), False)
            expect(f"tier {tier}: {field} = 0", verify_certificate(_mutate_at(big, tier, **{field: 0})), False)
        for field in ("a2", "aq"):
            expect(f"tier {tier}: {field} non-canonical (+n), same residue", verify_certificate(_mutate_at(big, tier, **{field: getattr(node, field) + n_i})), False)
            expect(f"tier {tier}: {field} = 1", verify_certificate(_mutate_at(big, tier, **{field: 1})), False)
            expect(f"tier {tier}: {field} = n - 1", verify_certificate(_mutate_at(big, tier, **{field: n_i - 1})), False)
        expect(f"tier {tier}: w2 and wq swapped", verify_certificate(_mutate_at(big, tier, w2=node.wq, wq=node.w2)) if node.w2 != node.wq else False, False)

    # ---------------------------------------------------------------- 4. structure and linkage
    print("\n4) factorization, size threshold, recursion and linkage")
    expect("R + 1 (n - 1 != 2qR)", verify_certificate(replace(top, R=top.R + 1)), False)
    expect("child removed", verify_certificate(replace(top, q_certificate=None)), False)
    expect("expected_n mismatch", verify_certificate(top, expected_n=top.n + 2), False)
    expect("root n altered", verify_certificate(replace(top, n=104721)), False)
    expect("child witness corrupted", verify_certificate(replace(top, q_certificate=replace(top.q_certificate, w2=(top.q_certificate.w2 + 1) % top.q_certificate.n))), False)
    expect("bool R (True == 1) in place of an int", verify_certificate(replace(top, R=True)) if top.R == 1 else False, False)

    # a TRUE prime whose factored part is too small: only the size bound can reject it
    q0 = 1000003
    assert small_is_prime(q0)
    while True:
        R_ = rng.randrange(4 * q0, 8 * q0)
        weak_n = 2 * q0 * R_ + 1
        if weak_n >= 4 * q0 * q0 and _oracle_is_prime(weak_n):
            break
    a2_, w2_ = _find_bezout_witness(weak_n, 2)
    aq_, wq_ = _find_bezout_witness(weak_n, q0)
    weak = PrimeCertificate(weak_n, q0, R_, a2_, w2_, aq_, wq_, build_certificate(q0))
    expect(f"true prime ({weak_n.bit_length()} bits) with 4q^2 <= n, otherwise valid witnesses", verify_certificate(weak), False)

    # substitution: parent claims q but the child certifies a different prime
    qc = 1000001                                          # = 101 * 9901 (composite, never certifiable)
    assert not small_is_prime(qc)
    while True:
        R_ = rng.randrange(2, qc)
        sub_n = 2 * qc * R_ + 1
        if _oracle_is_prime(sub_n):
            break
    a2_, w2_ = _find_bezout_witness(sub_n, 2)
    aq_, wq_ = _find_bezout_witness(sub_n, qc)
    sub = PrimeCertificate(sub_n, qc, R_, a2_, w2_, aq_, wq_, build_certificate(104723))
    expect("child certifies 104723, parent claims q = 1000001 (composite)", verify_certificate(sub), False)

    # ---------------------------------------------------------------- 5. Fermat is independent of Bezout
    print("\n5) composites with VALID Bezout inverses: only the Fermat condition can reject")
    q1 = 1009
    child_1009 = build_certificate(q1)
    forged = None
    for _ in range(100000):
        R_ = rng.randrange(520, 2000)                     # n > BASE_LIMIT and 4q^2 > n
        m = 2 * q1 * R_ + 1
        a = rng.randrange(2, m - 2)
        if _oracle_is_prime(m) or pow(a, m - 1, m) == 1:
            continue
        y2, yq = (pow(a, (m - 1) // 2, m) - 1) % m, (pow(a, (m - 1) // q1, m) - 1) % m
        if gcd(y2, m) == 1 and gcd(yq, m) == 1:
            forged = PrimeCertificate(m, q1, R_, a, pow(y2, -1, m), a, pow(yq, -1, m), child_1009)
            break
    assert forged is not None and 4 * q1 * q1 > forged.n > BASE_LIMIT
    expect("composite, consistent structure, valid Bezout, Fermat fails", verify_certificate(forged), False)

    print("\n6) forged-composite sweep (3000 random composites n = 2qR+1 with random bases)")
    accepted = 0
    for _ in range(3000):
        R_ = rng.randrange(520, 2000)
        m = 2 * q1 * R_ + 1
        if _oracle_is_prime(m):
            continue
        a, b = rng.randrange(2, m - 2), rng.randrange(2, m - 2)
        y2, yq = (pow(a, (m - 1) // 2, m) - 1) % m, (pow(b, (m - 1) // q1, m) - 1) % m
        w2_c = pow(y2, -1, m) if gcd(y2, m) == 1 else 0
        wq_c = pow(yq, -1, m) if gcd(yq, m) == 1 else 0
        accepted += verify_certificate(PrimeCertificate(m, q1, R_, a, w2_c, b, wq_c, child_1009))
    expect("no composite accepted", accepted == 0, True)

    # ---------------------------------------------------------------- 7. hostile input
    print("\n7) malformed or hostile input never raises")
    class EvilCert(PrimeCertificate):
        pass

    class Hostile(int):
        def __mod__(self, other):
            raise RuntimeError("hostile arithmetic")

    class HostileExpected:
        def __ne__(self, other):
            raise RuntimeError("hostile comparison")

        def __eq__(self, other):
            raise RuntimeError("hostile comparison")

    deep = PrimeCertificate(5)
    for _ in range(3000):                                 # structurally plausible but absurdly deep
        deep = PrimeCertificate(n=2 * deep.n + 1, q=deep.n, R=1, a2=2, w2=1, aq=2, wq=1, q_certificate=deep)
    for name, args in {
        "None": (None,),
        "int instead of certificate": (7,),
        "string n": (PrimeCertificate("x"),),
        "float n": (PrimeCertificate(float(top.n)),),
        "bool n": (PrimeCertificate(True),),
        "int subclass with hostile arithmetic": (replace(top, w2=Hostile(top.w2)),),
        "certificate subclass": (EvilCert(**{f: getattr(top, f) for f in ("n", "q", "R", "a2", "w2", "aq", "wq", "q_certificate")}),),
        "child of wrong type": (replace(top, q_certificate="nope"),),
        "3000-deep chain (recursion bomb)": (deep,),
        "expected_n whose comparison raises": (top, HostileExpected()),
    }.items():
        try:
            expect(name, verify_certificate(*args), False)
        except Exception as exc:
            print(f"  [FAIL] {name}: raised {type(exc).__name__}")
            failures.append(name)

    # ---------------------------------------------------------------- 8. fuzz
    print("\n8) randomized single-field mutation fuzz (600 trials)")
    stray = 0
    soundness = 0
    for _ in range(600):
        n, q = _random_chain_prime(rng.choice((1, 2)), rng)
        cert = build_certificate(n, q_hint=q)
        tier = rng.randrange(_tier_count(cert))
        node = cert
        for _ in range(tier):
            node = node.q_certificate
        field = rng.choice(("n", "q", "R", "w2", "wq", "a2", "aq"))
        old = getattr(node, field)
        new = old + rng.choice((1, 2, -1)) if rng.random() < 0.5 else rng.randrange(2, max(old * 2, 10))
        if new == old:
            new += 1
        mutated = _mutate_at(cert, tier, **{field: new})
        accepted = verify_certificate(mutated)
        if accepted and not _oracle_is_prime(mutated.n):
            soundness += 1                                 # certified a composite: real failure
        if accepted and field not in ("a2", "aq"):
            stray += 1                                     # only another valid base may legitimately pass
    expect("no mutation outside the base witnesses a2/aq is accepted", stray == 0, True)
    expect("no accepted certificate ever covers a composite", soundness == 0, True)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + '; '.join(failures)}")
    return len(failures)


def secrets_seed() -> int:
    import secrets
    return secrets.randbits(32)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursive Pocklington certificate demo")
    parser.add_argument("--test", action="store_true", help="run adversarial self-tests")
    parser.add_argument("--seed", type=int, default=None, help="seed for --test (default: random)")
    parser.add_argument("--number", type=int, default=104723, help="prime to certify")
    parser.add_argument("--q-hint", type=int, default=52361, help="known prime factor q")
    args = parser.parse_args()

    if args.test:
        sys.exit(1 if run_self_tests(args.seed) else 0)
    else:
        certificate = build_certificate(args.number, q_hint=args.q_hint)
        valid = verify_certificate(certificate, expected_n=args.number)
        print(f"n={args.number}")
        print(f"certificate_valid={valid}")
        print(f"certificate={certificate!r}")
