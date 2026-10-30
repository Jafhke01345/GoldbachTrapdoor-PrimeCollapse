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
"""

from dataclasses import dataclass
from math import isqrt
from typing import Optional
import argparse


BASE_BITS = 20
BASE_LIMIT = (1 << BASE_BITS) - 1


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
    # bool is a subclass of int in Python, so reject it explicitly.
    return isinstance(value, int) and not isinstance(value, bool)


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


def verify_certificate(
    cert: PrimeCertificate,
    expected_n: Optional[int] = None,
    _depth: int = 0,
) -> bool:
    """
    Verify a recursive Pocklington certificate.

    Returns False for malformed certificates instead of propagating ordinary
    input-related exceptions. The recursion depth is bounded defensively.
    """
    if _depth > 128 or not isinstance(cert, PrimeCertificate):
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
    if not isinstance(child, PrimeCertificate) or child.n != q:
        return False

    # Exact integer factorization and Pocklington size bound.
    if n - 1 != 2 * q * R:
        return False
    if 4 * q * q <= n:
        return False

    # Recursively establish that q is prime.
    if not verify_certificate(child, expected_n=q, _depth=_depth + 1):
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


def run_self_tests() -> None:
    """Small deterministic regression/adversarial test suite."""
    from dataclasses import replace

    # 104723 is a valid 20-bit base prime and exercises deterministic trial division.
    assert verify_certificate(build_certificate(104723)), "104723 base prime rejected"

    # Exercise the recursive Pocklington path with a prime just above 20 bits:
    # 2,097,779 = 2 * 1,048,889 * 1 + 1
    # 1,048,889 = 2 * 131,111 * 4 + 1
    cert = build_certificate(2_097_779, q_hint=1_048_889)
    assert verify_certificate(cert), "valid recursive certificate rejected"

    # Known composites, including Carmichael numbers, must fail the base case.
    carmichael_numbers = (561, 1105, 1729, 2465, 2821, 6601, 41041)
    for value in carmichael_numbers:
        assert not verify_certificate(PrimeCertificate(value)), (
            f"Carmichael number {value} was accepted"
        )

    assert not verify_certificate(PrimeCertificate(104721))
    assert not verify_certificate(PrimeCertificate(1))
    assert not verify_certificate(PrimeCertificate(2**20 + 1))  # no certificate

    # Corrupt each Bezout witness independently.
    assert not verify_certificate(replace(cert, w2=(cert.w2 + 1) % cert.n))
    assert not verify_certificate(replace(cert, wq=(cert.wq + 1) % cert.n))

    # Corrupt a witness in the child certificate too.
    child = cert.q_certificate
    assert child is not None
    assert not verify_certificate(
        replace(cert, q_certificate=replace(child, w2=(child.w2 + 1) % child.n))
    )

    # Break the factorization and recursive path.
    assert not verify_certificate(replace(cert, R=cert.R + 1))
    assert not verify_certificate(replace(cert, q_certificate=None))

    # A false base-prime assertion must fail deterministic trial division.
    assert not verify_certificate(PrimeCertificate(561))

    # Altering the certified root number must not preserve acceptance.
    assert not verify_certificate(replace(cert, n=104721))

    print("All Pocklington certificate tests passed.")
    print("104723 base case: accepted")
    print("2,097,779 recursive certificate: accepted")
    print("104721 and Carmichael test set: rejected")
    print("Corrupted Bezout witnesses, factorization, and chain: rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursive Pocklington certificate demo")
    parser.add_argument("--test", action="store_true", help="run adversarial self-tests")
    parser.add_argument("--number", type=int, default=104723, help="prime to certify")
    parser.add_argument("--q-hint", type=int, default=52361, help="known prime factor q")
    args = parser.parse_args()

    if args.test:
        run_self_tests()
    else:
        certificate = build_certificate(args.number, q_hint=args.q_hint)
        valid = verify_certificate(certificate, expected_n=args.number)
        print(f"n={args.number}")
        print(f"certificate_valid={valid}")
        print(f"certificate={certificate!r}")
