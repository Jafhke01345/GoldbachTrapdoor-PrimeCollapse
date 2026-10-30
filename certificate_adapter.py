"""
certificate_adapter.py - converts Pocklington certificates between the two formats in this repo and
cross-tests the two verifiers against each other.

    pocklington_chain.PrimeCertificate        nested, recursive, terminal prime below 2^20
    zk_primality_circuit.Step (flat list)     top-down, anchored to a Pedersen commitment, terminal below 2^32

The conversion is purely structural. It never decides primality: the verdict always comes from
one of the two verifiers. Anything malformed raises ValueError, and the cross-test counts that as
a rejection.

Run `python certificate_adapter.py` for the differential self-test:
    * every honest certificate is accepted by BOTH verifiers after conversion in either direction
    * random single-field mutations get the SAME verdict from both verifiers (no disagreement)

Educational toy: not zero-knowledge, unaudited.
"""
import random
import secrets
import sys
from dataclasses import replace
from typing import List, Tuple

import pocklington_chain as eng
import zk_primality_circuit as circ

MAX_TIERS = circ.MAX_STEPS


def from_engine(cert) -> Tuple[List[circ.Step], int]:
    """Nested engine certificate -> (flat circuit steps, root n). Raises ValueError if malformed."""
    if type(cert) is not eng.PrimeCertificate or type(cert.n) is not int:
        raise ValueError("not a PrimeCertificate")
    root = cert.n
    steps: List[circ.Step] = []
    node = cert
    while type(node) is eng.PrimeCertificate and type(node.n) is int and node.n > eng.BASE_LIMIT:
        if len(steps) >= MAX_TIERS:
            raise ValueError("too many tiers")
        child = node.q_certificate
        if type(child) is not eng.PrimeCertificate:
            raise ValueError("missing q_certificate")
        # the link the engine enforces and the circuit enforces differently: child must certify q
        if child.n != node.q:
            raise ValueError("q_certificate does not certify q")
        steps.append(circ.Step(node.n, node.q, node.R, node.a2, node.aq, node.w2, node.wq))
        node = child
    if type(node) is not eng.PrimeCertificate or type(node.n) is not int:
        raise ValueError("malformed terminal")
    return steps, root


def to_engine(steps: List[circ.Step], n: int):
    """Flat circuit steps -> nested engine certificate. Raises ValueError if the chain does not
    fit the engine (terminal prime must be below the engine's 2^20 trial-division limit)."""
    if not isinstance(steps, (list, tuple)) or len(steps) > MAX_TIERS:
        raise ValueError("bad steps")
    if any(type(s) is not circ.Step for s in steps):
        raise ValueError("not a Step")
    terminal = steps[-1].witness_q_val if steps else n
    if type(terminal) is not int or terminal > eng.BASE_LIMIT:
        raise ValueError("terminal prime exceeds the engine's base limit")
    cert = eng.PrimeCertificate(n=terminal)
    for s in reversed(steps):
        if type(s) is not circ.Step:
            raise ValueError("not a Step")
        cert = eng.PrimeCertificate(n=s.n, q=s.witness_q_val, R=s.witness_R, a2=s.witness_a2,
                                    w2=s.bezout_2, aq=s.witness_aq, wq=s.bezout_q, q_certificate=cert)
    return cert


def engine_verdict(cert, n=None) -> bool:
    return eng.verify_certificate(cert, n)


def circuit_verdict_from_engine(cert, params, r: int, root_n: int, C_n: int) -> bool:
    """Convert an engine certificate and run the circuit checker (conversion failure = reject)."""
    try:
        steps, root = from_engine(cert)
    except (ValueError, TypeError, AttributeError):
        return False
    return circ.verify(steps, C_n, root_n, r, params)


# ============================================================================ differential self-test
_ENGINE_FIELDS = ("n", "q", "R", "a2", "w2", "aq", "wq")


def _tiers(cert):
    out = []
    while cert is not None:
        out.append(cert)
        cert = cert.q_certificate
    return out


def _rebuild(tiers):
    cert = None
    for t in reversed(tiers):
        cert = replace(t, q_certificate=cert)
    return cert


def _selftest() -> int:
    seed = secrets.randbits(64)
    rng = random.Random(seed)
    print(f"seed={seed}")
    params = circ.make_params(272)
    P, Q, _, _ = params
    failures = []

    def expect(name, got, want):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def chain(levels):
        """Random provable prime with a full nested certificate, built bottom-up (no factoring)."""
        while True:
            q = rng.randrange(1 << 18, eng.BASE_LIMIT)
            if eng.small_is_prime(q):
                break
        cert = eng.PrimeCertificate(n=q)
        for _ in range(levels):
            q = cert.n
            while True:
                R = rng.randrange(2, q)                   # R < q  =>  4q^2 > n
                n = 2 * q * R + 1
                if eng._oracle_is_prime(n):
                    break
            a2, w2 = eng._find_bezout_witness(n, 2)
            aq, wq = eng._find_bezout_witness(n, q)
            cert = eng.PrimeCertificate(n=n, q=q, R=R, a2=a2, w2=w2, aq=aq, wq=wq, q_certificate=cert)
        return cert.n, cert

    print("\n1) engine -> circuit: honest certificates")
    for levels in (0, 1, 2, 3, 4):
        n, cert = chain(levels)
        if n >= Q:
            continue
        r = secrets.randbelow(Q)
        C = circ.commit(params, n, r)
        steps, root = from_engine(cert)
        expect(f"{levels} levels ({n.bit_length()}-bit): engine and converted-circuit both accept",
               (engine_verdict(cert, n), circ.verify(steps, C, root, r, params)), (True, True))

    print("\n2) circuit -> engine: honest certificates")
    for bits in (24, 64, 128, 200):
        steps = circ.build_certificate(bits)
        n = steps[0].n
        r = secrets.randbelow(Q)
        C = circ.commit(params, n, r)
        try:
            cert = to_engine(steps, n)
        except ValueError:
            expect(f"{bits}-bit: terminal beyond engine range is refused loudly, not mis-converted",
                   steps[-1].witness_q_val > eng.BASE_LIMIT, True)
            continue
        expect(f"{bits}-bit: both accept", (circ.verify(steps, C, n, r, params), engine_verdict(cert, n)), (True, True))
        back, root = from_engine(cert)
        expect(f"{bits}-bit: round trip circuit -> engine -> circuit is lossless", (back, root), (list(steps), n))

    print("\n3) the two verifiers use different formats but must give the same verdict")
    n, cert = chain(3)
    assert n < Q
    r = secrets.randbelow(Q)
    C = circ.commit(params, n, r)
    tiers = _tiers(cert)
    top = tiers[0]
    cases = {
        "top Bezout w2 + 1": replace(top, w2=(top.w2 + 1) % top.n),
        "top Bezout wq + 1": replace(top, wq=(top.wq + 1) % top.n),
        "top base a2 = 1": replace(top, a2=1),
        "top base aq = n - 1": replace(top, aq=top.n - 1),
        "top R + 1": replace(top, R=top.R + 1),
        "top q replaced": replace(top, q=top.q + 2),
    }
    for name, bad_top in cases.items():
        bad = _rebuild([bad_top] + tiers[1:])
        e = engine_verdict(bad, n)
        c = circuit_verdict_from_engine(bad, params, r, n, C)
        expect(f"{name}: engine={e} circuit={c}", (e, c), (False, False))
    bad = _rebuild(tiers[:1] + [replace(tiers[1], n=tiers[1].n + 2)] + tiers[2:])
    expect("child certifies a different n than q (engine and circuit must both reject)",
           (engine_verdict(bad, n), circuit_verdict_from_engine(bad, params, r, n, C)), (False, False))
    bad = _rebuild(tiers[:-1] + [replace(tiers[-1], n=tiers[-1].n + 1)])
    expect("terminal replaced by a different number", (engine_verdict(bad, n), circuit_verdict_from_engine(bad, params, r, n, C)), (False, False))

    print("\n4) differential fuzz: 600 random single-field mutations, verdicts must agree")
    disagreements, accepted_both, trials = 0, 0, 600
    for _ in range(trials):
        n, cert = chain(rng.choice((1, 2, 3)))
        if n >= Q:
            continue
        r = secrets.randbelow(Q)
        C = circ.commit(params, n, r)
        tiers = _tiers(cert)
        i = rng.randrange(len(tiers))
        field = rng.choice(_ENGINE_FIELDS) if i < len(tiers) - 1 else "n"
        old = getattr(tiers[i], field)
        if old is None:
            continue
        new = rng.choice((old + 1, old - 1, old ^ (1 << rng.randrange(max(1, old.bit_length()))), rng.randrange(2, max(3, old * 2))))
        if new == old:
            new = old + 1
        bad = _rebuild(tiers[:i] + [replace(tiers[i], **{field: new})] + tiers[i + 1:])
        e = engine_verdict(bad, n)
        c = circuit_verdict_from_engine(bad, params, r, n, C)
        if e != c:
            disagreements += 1
            print(f"    disagreement: tier {i} field {field}: engine={e} circuit={c}")
        accepted_both += (e and c)
    expect("no disagreement between engine and circuit verdicts", disagreements, 0)
    print(f"    ({accepted_both} mutated certificates were accepted by both: only possible via another valid base)")

    print("\n5) hostile input to the adapter raises ValueError only")
    for name, fn in {
        "from_engine(None)": lambda: from_engine(None),
        "from_engine(int)": lambda: from_engine(5),
        "to_engine(None)": lambda: to_engine(None, 7),
        "to_engine([None])": lambda: to_engine([None], 7),
        "to_engine over-long list": lambda: to_engine([circ.Step(1, 1, 1, 2, 2, 1, 1)] * 100, 7),
    }.items():
        try:
            fn()
            expect(name + " rejected", False, True)
        except ValueError:
            expect(name + " rejected", True, True)
        except Exception as exc:
            expect(f"{name}: wrong exception {type(exc).__name__}", False, True)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: conversion helper and test oracle only: NOT zero-knowledge, toy-size group, unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
