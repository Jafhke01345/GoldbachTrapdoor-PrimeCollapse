"""
goldbach_relation.py - the combined statement of this repo, as one checker:

    public  : c, and Pedersen commitments Ca, Cb (with the Schnorr midpoint proof and range proofs)
    opening : a, ra, b, rb  and a Pocklington certificate for each of a and b
    accept  : iff
        1. zkrp_toy.verify(pub)                      a + b = 2c mod Q, a and c - a in [0, 2^32), 0 <= c < 2^33
        2. Ca opens to a and Cb opens to b           (same group as step 1: the shared P, Q, G, H)
        3. the certificate for a proves a prime, likewise b   (zk_primality_circuit.verify)
        4. a + b == 2c and a <= c <= b over the integers

WHAT THIS IS NOT
    Not zero-knowledge for the primes: the openings (a, ra, b, rb) and the certificates are checked in
    the clear, so a verifier who runs this learns a and b. It is a reference RELATION CHECKER: it defines
    exactly what a zero-knowledge proof of "committed a and b are prime" would have to establish.
    Toy 256-bit group, 32-bit range, unaudited.

Run `python goldbach_relation.py` for the adversarial self-test.
"""
import random
import secrets
import sys
from dataclasses import dataclass, replace
from typing import List

import certificate_adapter as adapter
import pocklington_chain as eng
import zk_primality_circuit as circ
import zkrp_toy as Z

PARAMS = circ.Params(Z.P, Z.Q, Z.G, Z.H)     # the circuit checker opens commitments in zkrp_toy's group


@dataclass(frozen=True)
class Opening:
    n: int                                   # the committed prime
    r: int                                   # commitment randomness
    steps: tuple                             # flat Pocklington certificate (circuit format)


def certify(n: int) -> tuple:
    """Pocklington certificate for a known prime n, in the circuit's flat format.
    Raises ValueError if n is not a prime of the shape the engine can certify."""
    steps, _ = adapter.from_engine(eng.build_certificate(n))
    return tuple(steps)


def prove_relation(a: int, b: int):
    """Honest prover: returns (public transcript, opening of a, opening of b)."""
    witness = {}
    pub = Z.prove(a, b, _witness=witness)
    return pub, Opening(a, witness["ra"], certify(a)), Opening(b, witness["rb"], certify(b))


def _verify_relation(pub, oa, ob) -> bool:
    if type(oa) is not Opening or type(ob) is not Opening:
        return False
    if not Z.verify(pub):
        return False
    c = pub["c"]
    a, b = oa.n, ob.n
    # Defense in depth: given the checks above this is implied (mutation-tested as an equivalent mutant),
    # but the statement is cheap to state and check directly over the integers.
    if type(a) is not int or type(b) is not int or a + b != 2 * c or not (a <= c <= b):
        return False
    if not circ.verify(list(oa.steps), pub["Ca"], a, oa.r, PARAMS):
        return False
    return circ.verify(list(ob.steps), pub["Cb"], b, ob.r, PARAMS)


def verify_relation(pub, oa, ob) -> bool:
    """Total function: any malformed input yields False, never an exception."""
    try:
        return _verify_relation(pub, oa, ob)
    except Exception:
        return False


# ============================================================================ self-test
def _random_prime(rng: random.Random, lo: int, hi: int) -> int:
    while True:
        n = rng.randrange(lo | 1, hi, 2)
        if eng._oracle_is_prime(n):
            try:
                certify(n)
            except ValueError:
                continue
            return n


def _selftest() -> int:
    rng = random.Random(secrets.randbits(64))
    failures = []

    def expect(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    print("1) honest statements")
    pairs = [(5, 5), (3, 7), (13, 97)]
    for _ in range(3):
        a, b = sorted((_random_prime(rng, 1 << 21, 1 << 31), _random_prime(rng, 1 << 21, 1 << 31)))
        pairs.append((a, b))
    for a, b in pairs:
        pub, oa, ob = prove_relation(a, b)
        tiers = (len(oa.steps), len(ob.steps))
        expect(f"a={a} b={b} (tiers {tiers}): accepted", verify_relation(pub, oa, ob))

    print("\n2) non-prime endpoints")
    for a, b in ((15, 17), (9, 21), (1000001, 1000003)):
        pub = Z.prove(a, b)                                   # valid Pedersen/range proof, composite endpoint
        w = {}
        pub = Z.prove(a, b, _witness=w)
        for label, steps in (("no certificate", ()),):
            expect(f"composite endpoint in ({a}, {b}), {label}: rejected",
                   verify_relation(pub, Opening(a, w["ra"], steps), Opening(b, w["rb"], ())), False)
    a, b = pairs[-1]
    pub, oa, ob = prove_relation(a, b)
    w = {}
    comp = 3 * 5 * 7 * 11 * 13 * 17 * 19                       # odd composite, 4849845
    pub2 = Z.prove(comp, comp, _witness=w)
    expect("composite endpoint reusing a prime's certificate: rejected",
           verify_relation(pub2, Opening(comp, w["ra"], oa.steps), Opening(comp, w["rb"], ob.steps)), False)

    print("\n3) certificate and opening substitutions")
    a, b = pairs[-1]
    pub, oa, ob = prove_relation(a, b)
    expect("certificates swapped between a and b", verify_relation(pub, replace(oa, steps=ob.steps), replace(ob, steps=oa.steps)), False)
    other = _random_prime(rng, 1 << 21, 1 << 31)
    expect("certificate for a different prime", verify_relation(pub, replace(oa, steps=certify(other)), ob), False)
    expect("wrong randomness for Ca", verify_relation(pub, replace(oa, r=(oa.r + 1) % Z.Q), ob), False)
    expect("wrong randomness for Cb", verify_relation(pub, oa, replace(ob, r=(ob.r + 1) % Z.Q)), False)
    expect("opening of a claims a + 1", verify_relation(pub, replace(oa, n=oa.n + 1), ob), False)
    expect("openings swapped (a and b exchanged)", verify_relation(pub, ob, oa), a == b)
    pub_other, _, _ = prove_relation(*pairs[0])
    expect("proof from a different statement", verify_relation(pub_other, oa, ob), False)

    print("\n4) tampered public transcript")
    for field, fn in (("c", lambda v: v + 1), ("Ca", lambda v: v * Z.G % Z.P), ("Cb", lambda v: v * Z.G % Z.P),
                      ("z", lambda v: (v + 1) % Z.Q), ("T", lambda v: v * Z.G % Z.P)):
        bad = dict(pub); bad[field] = fn(bad[field])
        expect(f"{field} tampered", verify_relation(bad, oa, ob), False)

    print("\n5) integer-level attacks")
    expect("c claimed as c + Q (same residue)", verify_relation(dict(pub, c=pub["c"] + Z.Q), oa, ob), False)

    print("\n6) certificate mutation fuzz (300 trials; only an alternative valid base may still pass)")
    escapes = 0
    for _ in range(300):
        p1 = _random_prime(rng, 1 << 21, 1 << 31)
        pub, oa, ob = prove_relation(p1, p1)
        if not oa.steps:
            continue
        i = rng.randrange(len(oa.steps))
        fld = rng.choice(("n", "witness_q_val", "witness_R", "bezout_2", "bezout_q", "witness_a2", "witness_aq"))
        old = getattr(oa.steps[i], fld)
        new = rng.choice((old + 1, old - 1, rng.randrange(2, old * 2 + 3)))
        if new == old:
            new += 1
        steps = list(oa.steps); steps[i] = replace(steps[i], **{fld: new})
        ok = verify_relation(pub, replace(oa, steps=tuple(steps)), ob)
        if ok and fld not in ("witness_a2", "witness_aq"):
            escapes += 1
    expect("no mutation outside the base fields accepted", escapes, 0)

    print("\n7) hostile input never raises")
    class Evil(Opening):
        pass
    for name, args in {
        "None everything": (None, None, None),
        "pub is a list": ([], oa, ob),
        "opening is a tuple": (pub, (1, 2, 3), ob),
        "Opening subclass": (pub, Evil(oa.n, oa.r, oa.steps), ob),
        "steps is None": (pub, replace(oa, steps=None), ob),
        "n is a float": (pub, replace(oa, n=float(oa.n)), ob),
        "n is a bool": (pub, replace(oa, n=True), ob),
    }.items():
        try:
            expect(name, verify_relation(*args), False)
        except Exception as exc:
            print(f"  [FAIL] {name}: raised {type(exc).__name__}"); failures.append(name)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: relation checker only. The primes are opened in the clear: NOT zero-knowledge for primality. Toy, unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
