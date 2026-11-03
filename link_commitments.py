"""
link_commitments.py - proves that two commitments in two DIFFERENT groups hide the same integer a (0 <= a < 2^64):

    Ca = g^a h^ra          in the Pedersen group of zkrp_toy.py (a safe-prime subgroup, order Z.Q)
    C  = a*G + s*H         on the Stark elliptic curve of stark_curve.py (prime order SC.Q)

Why it is needed: the primality STARK (stark_primality.py) proves that the number inside C is prime, and the midpoint
and range proofs (zkrp_toy.py) work on Ca. This proof ties the two, so "the committed a is prime" and "a + b = 2c" are
statements about one number.

A Schnorr-style sigma protocol (made non-interactive with Fiat-Shamir) with ONE shared response z for the value:

    commit    k random integer in [0, 2^240),  u1 in Z_Zq,  u2 in Z_SCq
              T1 = g^k h^u1        T2 = k*G + u2*H
    challenge e = 128-bit hash of the whole statement and T1, T2
    respond   z = k + e*a  (a plain INTEGER, no reduction)     w1 = u1 + e*ra mod Z.Q     w2 = u2 + e*s mod SC.Q
    verify    g^z h^w1 = T1 * Ca^e    and    z*G + w2*H = T2 + e*C    and    0 <= z < 2^241

Why the integer response is the whole point: the two groups have different orders, so a reduced response z mod q would
mean different things in each. Here z stays an exact integer below 2^241, which is smaller than half of both group orders.
From two accepting transcripts with the same T1, T2 and challenges e != e', the difference D = z - z' satisfies
D = (e - e') * a_Z (mod Z.Q) and D = (e - e') * a_C (mod SC.Q). With a_Z and a_C below 2^64 (the range proof and the
STARK give that) both sides are integers below 2^192 and |D| < 2^241, all smaller than either order, so the congruences
are equalities of integers and a_Z = a_C. The bound on z is therefore load-bearing and checked. Zero knowledge:
k is 48 bits wider than e*a, so z is statistically 2^-48 close to uniform whatever a is (honest-verifier, Fiat-Shamir).

Educational toy: toy 256-bit group, unaudited, not constant-time.

Run `python link_commitments.py` for the adversarial self-test.
"""
import hashlib
import secrets
import sys

import stark_curve as SC
import zkrp_toy as Z

A_BITS = 64
CH_BITS = 128
SEC_BITS = 48
K_BITS = A_BITS + CH_BITS + SEC_BITS          # 240
Z_MAX = 1 << (K_BITS + 1)                      # accepted responses: 0 <= z < 2^241

KEYS = {"T1", "T2", "z", "w1", "w2"}


def _challenge(Ca, C, T1, T2):
    data = f"link_commitments|v1|{Z.P}|{Z.G}|{Z.H}|{SC.G}|{SC.H}|{Ca}|{C}|{T1}|{T2}".encode()
    return int.from_bytes(hashlib.sha256(data).digest(), "big") >> (256 - CH_BITS)


def prove(a, ra, s, _a_bound=True):
    """Return (Ca, C, proof) for a in [0, 2^64). `_a_bound=False` is a TEST HOOK for the wrap attack."""
    if type(a) is not int or (_a_bound and not 0 <= a < (1 << A_BITS)) or a < 0:
        raise ValueError("a out of range")
    Ca, C = Z.commit(a, ra), SC.commit(a, s)
    k = secrets.randbits(K_BITS)
    u1, u2 = secrets.randbelow(Z.Q), secrets.randbelow(SC.Q)
    T1 = pow(Z.G, k, Z.P) * pow(Z.H, u1, Z.P) % Z.P
    T2 = SC.add(SC.mul(k, SC.G), SC.mul(u2, SC.H))
    if T2 is None or C is None:
        raise ValueError("degenerate point")
    e = _challenge(Ca, C, T1, T2)
    return Ca, C, {"T1": T1, "T2": T2, "z": k + e * a, "w1": (u1 + e * ra) % Z.Q, "w2": (u2 + e * s) % SC.Q}


def verify(Ca, C, proof):
    """Total function: anything malformed gives False."""
    try:
        return _verify(Ca, C, proof)
    except Exception:
        return False


def _point(p):
    return type(p) is tuple and len(p) == 2 and SC.on_curve(p) and p is not None


def _verify(Ca, C, proof):
    if not Z._element(Ca) or not _point(C):
        return False
    if type(proof) is not dict or set(proof) != KEYS:
        return False
    T1, T2, z, w1, w2 = (proof[k] for k in ("T1", "T2", "z", "w1", "w2"))
    if not Z._element(T1) or not _point(T2):
        return False
    if type(z) is not int or not 0 <= z < Z_MAX:
        return False
    if not Z._scalar(w1) or type(w2) is not int or not 0 <= w2 < SC.Q:
        return False
    e = _challenge(Ca, C, T1, T2)
    if pow(Z.G, z, Z.P) * pow(Z.H, w1, Z.P) % Z.P != T1 * pow(Ca, e, Z.P) % Z.P:
        return False
    if SC.add(SC.mul(z, SC.G), SC.mul(w2, SC.H)) != SC.add(T2, SC.mul(e, C)):
        return False
    return True


# ============================================================================ self-test
def _selftest():
    import copy
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}", flush=True)
        if not ok:
            failures.append(name)

    print("0) parameters: the integer response must stay below half of both group orders")
    check("z bound < Z.Q / 2 and < SC.Q / 2", Z_MAX < Z.Q // 2 and Z_MAX < SC.Q // 2)
    check("e * a < 2^192 is far below both orders (no wrap in the extraction)", (1 << (CH_BITS + A_BITS)) < min(Z.Q, SC.Q) // 2)

    print("\n1) honest proofs")
    cases = [0, 1, (1 << 64) - 1] + [secrets.randbits(64) for _ in range(5)]
    good = None
    for a in cases:
        ra, s = secrets.randbelow(Z.Q), secrets.randbelow(SC.Q)
        Ca, C, pr = prove(a, ra, s)
        ok = verify(Ca, C, pr)
        if good is None:
            good = (a, ra, s, Ca, C, pr)
        check(f"a = {a}: accepted", ok)

    a, ra, s, Ca, C, pr = good
    print("\n2) the two commitments must hide the SAME number")
    check("C replaced by a commitment to a + 1 (same blinding): rejected", verify(Ca, SC.commit(a + 1, s), pr), False)
    check("Ca replaced by a commitment to a + 1 (same blinding): rejected", verify(Z.commit(a + 1, ra), C, pr), False)
    check("Ca re-randomised (same value): rejected (the proof is for these exact commitments)",
          verify(Z.commit(a, (ra + 1) % Z.Q), C, pr), False)
    check("C re-randomised (same value): rejected", verify(Ca, SC.commit(a, (s + 1) % SC.Q), pr), False)
    check("a proof for another pair of commitments is rejected", verify(*(lambda x: (x[0], x[1], pr))(prove(7, 1, 1)[:2])), False)
    a2 = (a + 5) % (1 << 64)
    Ca2, C2, pr2 = prove(a2, secrets.randbelow(Z.Q), secrets.randbelow(SC.Q))
    check("mixing the Ca of one proof with the C of another is rejected", verify(Ca, C2, pr2), False)

    print("\n3) the integer bound: a value that wraps modulo one group is rejected")
    wrap = a + SC.Q                                           # congruent to a modulo the curve order, but not below 2^64
    Cw, Cc, prw = prove(wrap, ra, s, _a_bound=False)
    check("a + SC.Q behaves like a on the curve side but its response exceeds 2^241: rejected", verify(Cw, Cc, prw), False)
    check("the response of that proof really is above the bound", prw["z"] >= Z_MAX)
    check("an honest response is below the bound", pr["z"] < Z_MAX)
    try:
        prove(1 << 64, 1, 1)
        check("a = 2^64 is refused by the prover", False)
    except ValueError:
        check("a = 2^64 is refused by the prover", True)

    print("\n4) every field of an honest proof is tied down")

    def mutate(label, fn):
        p = copy.deepcopy(pr)
        fn(p)
        check(f"{label}: rejected", verify(Ca, C, p), False)

    mutate("z + 1", lambda p: p.__setitem__("z", p["z"] + 1))
    mutate("z + 2^241 (above the bound)", lambda p: p.__setitem__("z", p["z"] + Z_MAX))
    mutate("z negative", lambda p: p.__setitem__("z", -1))
    mutate("w1 + 1", lambda p: p.__setitem__("w1", (p["w1"] + 1) % Z.Q))
    mutate("w1 + Q (non-canonical)", lambda p: p.__setitem__("w1", p["w1"] + Z.Q))
    mutate("w2 + 1", lambda p: p.__setitem__("w2", (p["w2"] + 1) % SC.Q))
    mutate("w2 + SC.Q (non-canonical)", lambda p: p.__setitem__("w2", p["w2"] + SC.Q))
    mutate("T1 replaced", lambda p: p.__setitem__("T1", Z.commit(1, 1)))
    mutate("T1 negated (outside the subgroup)", lambda p: p.__setitem__("T1", Z.P - p["T1"]))
    mutate("T2 replaced", lambda p: p.__setitem__("T2", SC.commit(1, 1)))
    mutate("T2 off the curve", lambda p: p.__setitem__("T2", (p["T2"][0], (p["T2"][1] + 1) % SC.P)))
    mutate("T2 as a list", lambda p: p.__setitem__("T2", list(p["T2"])))
    mutate("unknown extra key", lambda p: p.__setitem__("extra", 1))
    mutate("a key missing", lambda p: p.pop("w2"))
    check("None rejected", verify(Ca, C, None), False)
    check("a commitment off the curve rejected", verify(Ca, (C[0], (C[1] + 1) % SC.P), pr), False)
    check("a non-subgroup Ca rejected", verify(Z.P - Ca, C, pr), False)

    print("\n4b) checks that only a crafted forgery can tell apart (each one is load-bearing)")
    L = Z.Q * SC.Q                                            # both equations only see z modulo the group orders
    p = copy.deepcopy(pr)
    p["z"] -= L
    check("z - Z.Q*SC.Q satisfies both equations but is negative: rejected by the lower bound",
          verify(Ca, C, p), False)
    e0 = _challenge(Ca, C, pr["T1"], pr["T2"])
    alt = {"Ca": _challenge(Z.commit(1, 1), C, pr["T1"], pr["T2"]),
           "C": _challenge(Ca, SC.commit(1, 1), pr["T1"], pr["T2"]),
           "T1": _challenge(Ca, C, Z.commit(1, 1), pr["T2"]),
           "T2": _challenge(Ca, C, pr["T1"], SC.commit(1, 1))}
    for name, e1 in alt.items():
        check(f"the Fiat-Shamir challenge depends on {name}", e1 != e0)

    def forge(Ca_f, C_f, a_f, ra_f, s_f, want_even):
        """Honest-looking response for statement (Ca_f, C_f) whose values are known; grind until the challenge is even."""
        for _ in range(400):
            k = secrets.randbits(K_BITS)
            u1, u2 = secrets.randbelow(Z.Q), secrets.randbelow(SC.Q)
            T1 = pow(Z.G, k, Z.P) * pow(Z.H, u1, Z.P) % Z.P
            T2 = SC.add(SC.mul(k, SC.G), SC.mul(u2, SC.H))
            e = _challenge(Ca_f, C_f, T1, T2)
            if not want_even or e % 2 == 0:
                return {"T1": T1, "T2": T2, "z": k + e * a_f, "w1": (u1 + e * ra_f) % Z.Q, "w2": (u2 + e * s_f) % SC.Q}
        raise RuntimeError("no even challenge found")

    # the identity point as C: (0*G + 0*H); only the explicit curve-point check refuses it
    ra0 = secrets.randbelow(Z.Q)
    Ca0 = Z.commit(0, ra0)
    pf = forge(Ca0, None, 0, ra0, 0, False)
    check("C = identity with a matching forged response: rejected (point check)", verify(Ca0, None, pf), False)
    # -Ca (outside the subgroup) with an EVEN challenge: Ca^e = (-Ca)^e, so only the subgroup test stops it
    Cneg = Z.P - Ca
    pf = forge(Cneg, C, a, ra, s, True)
    check("-Ca (not in the subgroup) with an even challenge: rejected (subgroup check)", verify(Cneg, C, pf), False)
    # T1 in the subgroup and T2 on the curve are implied by the two equations once Ca and C are checked; the explicit
    # tests are defence in depth, so removing them is a documented equivalent mutation.

    print("\n5) special soundness and statistical hiding of the integer response")
    # two responses with the same commitment and different challenges give back the integer a exactly
    k = secrets.randbits(K_BITS)
    e1, e2 = secrets.randbits(CH_BITS), secrets.randbits(CH_BITS)
    z1, z2 = k + e1 * a, k + e2 * a
    check("(z1 - z2) = (e1 - e2) * a exactly over the integers", (z1 - z2) == (e1 - e2) * a)
    check("... and the extracted value fits both groups (no reduction happened)", (z1 - z2) // (e1 - e2) == a if e1 != e2 else True)
    lo = [prove(0, 1, 1)[2]["z"] / (1 << K_BITS) for _ in range(150)]
    hi = [prove((1 << 64) - 1, 1, 1)[2]["z"] / (1 << K_BITS) for _ in range(150)]
    m_lo, m_hi = sum(lo) / len(lo), sum(hi) / len(hi)
    print(f"    mean z / 2^240: a = 0 -> {m_lo:.3f}, a = 2^64 - 1 -> {m_hi:.3f} (a uniform response averages 0.5)")
    check("the response does not depend on a (mean of z for a = 0 and a = 2^64 - 1 agree)", abs(m_lo - m_hi) < 0.15)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy groups, zero knowledge argued (statistical, Fiat-Shamir), unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
