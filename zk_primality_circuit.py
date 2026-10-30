"""
zk_primality_circuit.py - relation checker for Pocklington-chain primality certificates,
anchored to a public Pedersen commitment.  Pure Python, standard library only.

WHAT THIS IS
    The *relation* that a zero-knowledge circuit (SNARK/STARK) would have to enforce:

        public : C_n = g^n * h^r  (mod P)       a Pedersen commitment
        witness: n, r, and a multi-tier Pocklington certificate for n
        accept : iff C_n opens to n AND the certificate proves n prime

    verify() is an active checking engine: every constraint is evaluated, and any mismatch
    returns False. It never raises on malformed input.

WHAT THIS IS NOT
    * Not zero-knowledge. verify() needs n, r and the whole certificate in the clear, so
      it reveals everything. Hiding n requires compiling these same constraints into a
      proof system (arkworks / halo2 / circom); this file is the reference for what that
      circuit must check, and a test oracle for it.
    * Not audited, not constant-time, not production cryptography.

CERTIFICATE FORMAT (top-down; step k certifies step k's `n`, using the prime below it)
    n = 2 * q * R + 1,   q = witness_q_val  (the prime certified by the NEXT step)
    Pocklington with F = 2q:   4q^2 > n   and, for EACH prime factor f of F, its own base a_f
    (witness_a2 for f = 2, witness_aq for f = q; they may be equal or different):
        a_f^(n-1) == 1 (mod n)
        gcd(a_f^((n-1)/f) - 1, n) == 1   proven by a Bezout witness:  (u_f - 1) * bezout_f == 1 (mod n)
    This is the same per-factor structure as pocklington_chain.PrimeCertificate, and
    certificate_adapter.py converts between the two (flat list here, nested there).
    The last step's q must be a small prime (< BASE_LIMIT), checked by trial division.

Run `python zk_primality_circuit.py` for the built-in adversarial self-test.
"""
import hashlib
import secrets
import sys
import time
from dataclasses import dataclass, replace
from math import gcd, isqrt
from typing import List, NamedTuple, Optional, Sequence

BASE_LIMIT = 1 << 32        # terminal prime must be below this (trial division is exact here)
MAX_N_BITS = 4096           # refuse absurdly large inputs (denial-of-service guard)
MAX_STEPS = 64


# ============================================================================ number theory
def is_small_prime(n: int) -> bool:
    """Exact trial division; only used below BASE_LIMIT (at most ~32k iterations)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin. Used for group setup and as an independent oracle in the self-test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
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


# ============================================================================ Pedersen group
class Params(NamedTuple):
    P: int      # safe prime, P = 2Q + 1
    Q: int      # prime order of the subgroup of squares
    G: int
    H: int


def _hash_to_subgroup(label: bytes, p: int) -> int:
    """Nothing-up-my-sleeve subgroup element (SHA-256 expand, then square): log_g(h) unknown."""
    ctr = 0
    while True:
        blocks = (p.bit_length() + 255) // 256 + 1
        digest = b"".join(hashlib.sha256(label + ctr.to_bytes(4, "big") + i.to_bytes(2, "big")).digest()
                          for i in range(blocks))
        x = pow(int.from_bytes(digest, "big") % p, 2, p)
        if x not in (0, 1):
            return x
        ctr += 1


def make_params(bits: int) -> Params:
    """Generate a safe-prime group. The committed value must be < Q, so pick bits > bitlen(n)."""
    small = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, isqrt(p) + 1, 2))]
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        p = 2 * q + 1
        if any(q % s == 0 or p % s == 0 for s in small):
            continue
        if is_probable_prime(q) and is_probable_prime(p):
            return Params(p, q, _hash_to_subgroup(b"zkpp-g", p), _hash_to_subgroup(b"zkpp-h", p))


def commit(params: Params, m: int, r: int) -> int:
    P, Q, G, H = params
    return pow(G, m % Q, P) * pow(H, r % Q, P) % P


def _params_ok(params) -> bool:
    try:
        P, Q, G, H = params
    except (TypeError, ValueError):
        return False
    if any(type(v) is not int for v in (P, Q, G, H)):
        return False
    if P != 2 * Q + 1 or Q < 5 or not (1 < G < P) or not (1 < H < P) or G == H:
        return False
    return pow(G, Q, P) == 1 and pow(H, Q, P) == 1       # both generators lie in the order-Q subgroup


# ============================================================================ certificate
@dataclass(frozen=True)
class Step:
    n: int                  # prime certified by this tier
    witness_q_val: int      # q: the (already certified) prime used as the factor of n - 1; next tier's n
    witness_R: int          # cofactor, n = 2 * q * R + 1
    witness_a2: int         # Pocklington base for the factor 2
    witness_aq: int         # Pocklington base for the factor q (may differ from witness_a2)
    bezout_2: int           # inverse of (a^((n-1)/2) - 1) mod n
    bezout_q: int           # inverse of (a^((n-1)/q) - 1) mod n


def transcript_digest(C_n: int, steps: Sequence[Step]) -> str:
    """SHA-256 over the commitment and the certificate, for binding a certificate to a statement
    (e.g. as the Fiat-Shamir input once this relation is wrapped in a real proof system)."""
    h = hashlib.sha256()
    h.update(b"zkpp-transcript|" + str(C_n).encode())
    for s in steps:
        h.update(b"|" + b",".join(str(v).encode() for v in
                                  (s.n, s.witness_q_val, s.witness_R, s.witness_a2, s.witness_aq, s.bezout_2, s.bezout_q)))
    return h.hexdigest()


# ============================================================================ the checker
def _is_int(*vals) -> bool:
    return all(type(v) is int for v in vals)         # rejects bool, float, str, None, ...


def _verify(steps, C_n, n, r, params) -> bool:
    if not _params_ok(params):
        return False
    P, Q, _, _ = params
    if not _is_int(C_n, n, r) or not (1 < C_n < P) or not (0 < n < Q) or not (0 <= r < Q):
        return False
    if n.bit_length() > MAX_N_BITS or not isinstance(steps, (list, tuple)) or len(steps) > MAX_STEPS:
        return False

    # ---- identity linkage: the root of the chain must be the value inside the public commitment
    lhs, rhs = commit(params, n, r), C_n
    if lhs != rhs:
        return False

    current_n = n
    for step in steps:
        if type(step) is not Step:          # exact type: no subclasses with hostile properties
            return False
        n_i, q, R = step.n, step.witness_q_val, step.witness_R
        a2, aq = step.witness_a2, step.witness_aq
        w2, wq = step.bezout_2, step.bezout_q
        if not _is_int(n_i, q, R, a2, aq, w2, wq):
            return False

        # ---- recursive chain link: this tier must certify exactly the value handed down from above
        if n_i != current_n:
            return False
        if q < 2 or R < 1:
            return False

        # ---- structure and Pocklington size threshold, over the integers (no modular wrap)
        if n_i != 2 * q * R + 1:
            return False
        if not (4 * q * q > n_i):                   # F = 2q must exceed sqrt(n)
            return False

        # ---- per prime factor f of F = 2q: its own base, Fermat condition, explicit Bezout witness
        for f, a, w in ((2, a2, w2), (q, aq, wq)):
            if not (2 <= a <= n_i - 2):             # canonical base, same range as pocklington_chain
                return False
            if pow(a, n_i - 1, n_i) != 1:           # Fermat condition for this base
                return False
            if not (0 <= w < n_i):                  # canonical range: no malleable witnesses
                return False
            if (n_i - 1) % f != 0:
                return False
            u = pow(a, (n_i - 1) // f, n_i)
            lhs, rhs = ((u - 1) * w) % n_i, 1       # exists iff gcd(u - 1, n) == 1
            if lhs != rhs:
                return False

        current_n = q                               # descend: the next tier must certify q

    # ---- terminal gate: the chain may only end at a verified small prime
    return current_n < BASE_LIMIT and is_small_prime(current_n)


def verify(steps: Sequence[Step], C_n: int, n: int, r: int, params: Params) -> bool:
    """True iff C_n == g^n h^r and `steps` is a valid Pocklington chain proving n prime.
    Total function: malformed input yields False, never an exception."""
    try:
        return _verify(steps, C_n, n, r, params)
    except Exception:                       # a verifier must fail closed on ANY error, incl. hostile objects
        return False


# ============================================================================ prover side (for tests)
def _witness_for(n: int, q: int) -> Optional[Step]:
    """Find a base and Bezout inverse for EACH factor of F = 2q (bases chosen independently, at random
    among the small valid ones, so that tests exercise a2 != aq); None if no witness exists."""
    R = (n - 1) // (2 * q)
    found = {}
    for f in (2, q):
        good = []
        for a in range(2, min(300, n - 1)):
            if pow(a, n - 1, n) != 1:
                return None                           # Fermat failure: n is composite
            y = (pow(a, (n - 1) // f, n) - 1) % n
            if gcd(y, n) == 1:
                good.append((a, pow(y, -1, n)))
        if not good:
            return None
        found[f] = secrets.choice(good)
    (a2, w2), (aq, wq) = found[2], found[q]
    return Step(n, q, R, a2, aq, w2, wq)


def build_certificate(bits: int) -> List[Step]:
    """Random provable prime of about `bits` bits. Returns steps top-down (empty if tiny)."""
    chain: List[Step] = []

    def rec(b: int) -> int:
        if b <= 20:
            while True:
                c = secrets.randbits(b) | (1 << (b - 1)) | 1
                if is_small_prime(c):
                    return c
        q = rec(b // 2 + 1)
        rb = max(2, b - q.bit_length() - 1)
        while True:
            R = secrets.randbits(rb) | (1 << (rb - 1))
            n = 2 * q * R + 1
            step = _witness_for(n, q)
            if step is not None and 4 * q * q > n:
                chain.append(step)
                return n

    rec(bits)
    return chain[::-1]


def root_of(steps: Sequence[Step], fallback: int) -> int:
    return steps[0].n if steps else fallback


# ============================================================================ adversarial self-test
def _selftest() -> int:
    t_start = time.time()
    print("generating Pedersen group (272-bit safe prime)...", flush=True)
    params = make_params(272)
    P, Q, _, _ = params
    failures = []

    def expect(name: str, got: bool, want: bool):
        ok = (got == want)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def fresh(bits: int):
        steps = build_certificate(bits)
        n = steps[0].n
        r = secrets.randbelow(Q)
        return steps, n, r, commit(params, n, r)

    print("\n1) honest certificates")
    for bits in (24, 64, 128, 256):
        steps, n, r, C = fresh(bits)
        expect(f"{bits}-bit prime, {len(steps)} tiers: accepted", verify(steps, C, n, r, params), True)
        assert is_probable_prime(n)
    tiny = 65537
    r = secrets.randbelow(Q)
    expect("zero-tier chain (n is itself a small prime): accepted", verify([], commit(params, tiny, r), tiny, r, params), True)

    print("\n2) commitment / identity-linkage attacks")
    steps, n, r, C = fresh(128)
    expect("wrong opening randomness r", verify(steps, C, n, (r + 1) % Q, params), False)
    expect("commitment to a different value", verify(steps, commit(params, n + 2, r), n, r, params), False)
    expect("claimed n differs from committed n", verify(steps, C, n + 2, r, params), False)
    other = fresh(128)
    expect("certificate for a different prime", verify(other[0], C, n, r, params), False)
    expect("n >= group order Q (would not bind the integer)", verify(steps, C, n + Q, r, params), False)
    big_steps = build_certificate(300)                  # prime wider than Q (271 bits)
    nb, rb = big_steps[0].n, secrets.randbelow(Q)
    assert nb >= Q and is_probable_prime(nb)
    expect("binding attack: C commits to (n mod Q), claim the large prime n",
           verify(big_steps, commit(params, nb % Q, rb), nb, rb, params), False)
    expect("n >= Q: even an honest commitment is refused (value would wrap mod Q)",
           verify(big_steps, commit(params, nb, rb), nb, rb, params), False)

    print("\n3) Bezout witness attacks")
    for i in range(len(steps)):
        s = steps[i]
        for field in ("bezout_2", "bezout_q"):
            bad = list(steps)
            bad[i] = replace(s, **{field: (getattr(s, field) + 1) % s.n})
            expect(f"tier {i}: {field} + 1", verify(bad, C, n, r, params), False)
        bad = list(steps)
        bad[i] = replace(s, bezout_2=s.bezout_q, bezout_q=s.bezout_2)
        if s.bezout_2 != s.bezout_q:
            expect(f"tier {i}: Bezout witnesses swapped", verify(bad, C, n, r, params), False)
        bad[i] = replace(s, bezout_2=s.bezout_2 + s.n)
        expect(f"tier {i}: non-canonical witness (w + n)", verify(bad, C, n, r, params), False)
        bad[i] = replace(s, bezout_q=0)
        expect(f"tier {i}: zero witness", verify(bad, C, n, r, params), False)

    print("\n4) broken recursion / structure attacks")
    if len(steps) >= 2:
        bad = list(steps); bad[1] = replace(bad[1], n=bad[1].n + 2)
        expect("chain link broken (tier 1 certifies a different n)", verify(bad, C, n, r, params), False)
        bad = list(steps); bad[0], bad[1] = bad[1], bad[0]
        expect("tiers reordered", verify(bad, C, n, r, params), False)
        bad = list(steps); del bad[1]
        expect("middle tier removed", verify(bad, C, n, r, params), False)
    trunc = list(steps)[:-1]
    got = verify(trunc, C, n, r, params)
    term = trunc[-1].witness_q_val if trunc else n
    expect(f"last tier removed (terminal {term.bit_length()}-bit): accepted only if terminal is a small prime",
           got, term < BASE_LIMIT and is_small_prime(term))
    bad = list(steps); bad[0] = replace(bad[0], witness_R=bad[0].witness_R + 1)
    expect("R tampered (n != 2qR + 1)", verify(bad, C, n, r, params), False)
    for fld in ("witness_a2", "witness_aq"):
        bad = list(steps); bad[0] = replace(bad[0], **{fld: 1})
        expect(f"{fld} = 1", verify(bad, C, n, r, params), False)
        bad = list(steps); bad[0] = replace(bad[0], **{fld: bad[0].n - 1})
        expect(f"{fld} = n - 1", verify(bad, C, n, r, params), False)
        bad = list(steps); bad[0] = replace(bad[0], **{fld: getattr(bad[0], fld) + bad[0].n})
        expect(f"{fld} non-canonical (a + n): same residue, rejected to keep the encoding unique", verify(bad, C, n, r, params), False)
    s0 = steps[0]
    bad = list(steps); bad[0] = replace(s0, witness_a2=s0.witness_aq, witness_aq=s0.witness_a2)
    if s0.witness_a2 != s0.witness_aq:
        expect("bases swapped between the two factors (each base is bound to its own Bezout witness)",
               verify(bad, C, n, r, params), False)

    print("\n5) size threshold: a TRUE prime whose certificate is too weak must be rejected")
    q = 1000003                                     # prime
    assert is_small_prime(q)
    while True:
        R = secrets.randbits(40) | (1 << 39)
        cand = 2 * q * R + 1
        if cand >= 4 * q * q and is_probable_prime(cand) and _witness_for(cand, q):
            break
    weak = _witness_for(cand, q)
    rr = secrets.randbelow(Q)
    expect(f"n is prime ({cand.bit_length()} bits) but 4q^2 <= n", verify([weak], commit(params, cand, rr), cand, rr, params), False)
    assert not (4 * q * q > cand)

    print("\n6) terminal base-prime gate")
    qc = 1000001                                    # = 101 * 9901, composite
    assert not is_small_prime(qc)
    while True:
        R = secrets.randbelow(qc - 1) + 1
        cand = 2 * qc * R + 1
        if is_probable_prime(cand) and _witness_for(cand, qc):
            break
    comp_chain = [_witness_for(cand, qc)]
    rr = secrets.randbelow(Q)
    expect("chain ends at a composite 'base'", verify(comp_chain, commit(params, cand, rr), cand, rr, params), False)
    big_prime = steps[-1].n if len(steps) else n
    big_chain = steps[:1]
    top_q = big_chain[0].witness_q_val
    if top_q >= BASE_LIMIT:
        expect("chain ends at a large (uncertified) prime", verify(big_chain, C, n, r, params), False)

    print("\n7) composite targets")
    for _ in range(3):
        qq = 1009
        while True:
            R = secrets.randbits(12) | (1 << 11)
            m = 2 * qq * R + 1
            if not is_probable_prime(m):
                break
        rr = secrets.randbelow(Q)
        fake = Step(m, qq, R, 2, 2, 1, 1)
        expect("composite n = 2qR + 1 with forged witnesses", verify([fake], commit(params, m, rr), m, rr, params), False)

    print("\n7b) composite with VALID Bezout witnesses: only the Fermat condition can reject it")
    forged = None
    for _ in range(20000):
        qq = 1009
        R = secrets.randbelow(1008) + 1                 # keeps 4q^2 > n
        m = 2 * qq * R + 1
        a = secrets.randbelow(m - 3) + 2
        if is_probable_prime(m) or pow(a, m - 1, m) == 1:
            continue
        u2, uq = pow(a, (m - 1) // 2, m), pow(a, (m - 1) // qq, m)
        if gcd(u2 - 1, m) == 1 and gcd(uq - 1, m) == 1:
            forged = Step(m, qq, R, a, a, pow(u2 - 1, -1, m), pow(uq - 1, -1, m))
            break
    assert forged is not None and 4 * 1009 * 1009 > forged.n
    rr = secrets.randbelow(Q)
    expect("composite, consistent structure, valid Bezout inverses, Fermat fails",
           verify([forged], commit(params, forged.n, rr), forged.n, rr, params), False)

    print("\n8) malformed or hostile input never raises")
    class BadList(list):
        def __len__(self):
            raise RuntimeError("hostile __len__")

    class EvilStep(Step):
        def __getattribute__(self, name):
            if name == "witness_aq":
                raise RuntimeError("hostile attribute access")
            return super().__getattribute__(name)

    for name, args in {
        "hostile list subclass (len() raises)": (BadList(steps), C, n, r, params),
        "hostile Step subclass (property raises)": ([EvilStep(*[getattr(steps[0], f) for f in
                                                     ("n", "witness_q_val", "witness_R", "witness_a2", "witness_aq", "bezout_2", "bezout_q")])] + list(steps[1:]), C, n, r, params),
        "steps=None": (None, C, n, r, params),
        "steps contains None": ([None], C, n, r, params),
        "float n": (steps, C, float(n), r, params),
        "bool r": (steps, C, n, True, params),
        "bool r that equals the committed value (True == 1)": (steps, commit(params, n, 1), n, True, params),
        "str C": (steps, "x", n, r, params),
        "bad params": (steps, C, n, r, (4, 1, 2, 3)),
        "too many steps": ([steps[0]] * 100, C, n, r, params),
        "Step with None field": (steps[:1] and [replace(steps[0], witness_aq=None)], C, n, r, params),
    }.items():
        try:
            expect(name, verify(*args), False)
        except Exception as exc:                         # verify must be total
            print(f"  [FAIL] {name}: raised {type(exc).__name__}")
            failures.append(name)

    print("\n9) randomized single-field mutation fuzz (400 trials per field group)")
    def mutate(v: int, hi: int) -> int:
        choice = secrets.randbelow(3)
        out = v + 1 if choice == 0 else (v ^ (1 << secrets.randbelow(max(1, v.bit_length())))) if choice == 1 else secrets.randbelow(hi)
        return out if out != v else v + 1
    escapes, soundness_violations, trials = 0, 0, 0
    for _ in range(400):
        steps, n, r, C = fresh(secrets.choice((48, 96, 160)))
        i = secrets.randbelow(len(steps))
        field = secrets.choice(("n", "witness_q_val", "witness_R", "bezout_2", "bezout_q", "witness_a2", "witness_aq", "root_n", "root_r", "C_n"))
        bad, bn, br, bC = list(steps), n, r, C
        if field == "root_n":   bn = mutate(n, Q)
        elif field == "root_r": br = mutate(r, Q)
        elif field == "C_n":    bC = mutate(C, P)
        else:
            old = getattr(steps[i], field)
            bad[i] = replace(steps[i], **{field: mutate(old, max(old * 2, 10))})
        accepted = verify(bad, bC, bn, br, params)
        trials += 1
        if accepted and bn == n and is_probable_prime(bn) is False:
            soundness_violations += 1                    # accepted a composite: real soundness failure
        if accepted and field not in ("witness_a2", "witness_aq"):
            escapes += 1                                 # only a different valid base may legitimately pass
    expect(f"{trials} mutations: no mutation outside the base fields accepted", escapes == 0, True)
    expect("no accepted transcript ever certified a composite", soundness_violations == 0, True)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}"
          f"   ({time.time() - t_start:.1f}s)")
    print("Reminder: relation checker only: NOT zero-knowledge, toy-size group, unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
