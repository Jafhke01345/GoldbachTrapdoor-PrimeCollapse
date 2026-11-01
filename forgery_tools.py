"""
forgery_tools.py - test helpers that build transcripts which are algebraically consistent but encoded in a
way an honest prover never produces, to check that the verifiers reject them (malleability and
small-subgroup attacks). Used by benchmark.py and test_fast.py. Not part of the protocol.
"""
import copy
import secrets

import zkrp_toy as Z


def _neg(x):
    return Z.P - x                      # multiplication by -1, an element of order 2 outside the order-Q subgroup


def _or_prove_negated(B_true, bit, r, ctx):
    """Valid OR-proof for the NEGATED bit commitment B' = -B_true (not in the prime-order subgroup).
    The real branch only verifies when its challenge is even, so we retry until it is."""
    Bn = _neg(B_true)
    Y = [Bn, Bn * Z.G_INV % Z.P]
    real, sim = bit, 1 - bit
    while True:
        e_sim, z_sim = secrets.randbelow(Z.Q), secrets.randbelow(Z.Q)
        T = [None, None]
        T[sim] = pow(Z.H, z_sim, Z.P) * pow(Y[sim], -e_sim, Z.P) % Z.P       # true inverse: Y has order 2Q
        t = secrets.randbelow(Z.Q)
        T[real] = pow(Z.H, t, Z.P)
        e = Z.challenge(ctx, Bn, T[0], T[1])
        e_real = (e - e_sim) % Z.Q
        if e_real % 2 == 0:
            break
    z_real = (t + e_real * r) % Z.Q
    es, zs = [None, None], [None, None]
    es[real], es[sim] = e_real, e_sim
    zs[real], zs[sim] = z_real, z_sim
    return Bn, (T[0], T[1], es[0], es[1], zs[0], zs[1])


def _range_prove_negated(m, r, n, ctx):
    """Range proof for the negated commitment -(g^m h^r): only bit 0 is negated, so the product of
    B_i^(2^i) is -C exactly."""
    bits = [(m >> i) & 1 for i in range(n)]
    rs = [secrets.randbelow(Z.Q) for _ in range(n)]
    rs[0] = (r - sum(rs[i] * (1 << i) for i in range(1, n))) % Z.Q
    Bs = [Z.commit(bits[i], rs[i]) for i in range(n)]
    proofs = [None] * n
    Bs[0], proofs[0] = _or_prove_negated(Bs[0], bits[0], rs[0], f"{ctx}:0")
    for i in range(1, n):
        proofs[i] = Z.or_prove(Bs[i], bits[i], rs[i], f"{ctx}:{i}")
    return Bs, proofs


def negated_transcript(a, b):
    """Transcript for the same statement but with Ca and Cb multiplied by -1. Every verification equation
    holds (the signs cancel in Ca*Cb); only a subgroup-membership check can reject it."""
    c = (a + b) // 2
    x = c - a
    ra, rb = secrets.randbelow(Z.Q), secrets.randbelow(Z.Q)
    Ca, Cb = _neg(Z.commit(a, ra)), _neg(Z.commit(b, rb))
    rp_a = _range_prove_negated(a, ra, Z.N_BITS, "a")
    rp_x = _range_prove_negated(x, (-ra) % Z.Q, Z.N_BITS, "x")
    s = (ra + rb) % Z.Q
    t = secrets.randbelow(Z.Q)
    T = pow(Z.H, t, Z.P)
    z = (t + Z.challenge(c, Ca, Cb, T) * s) % Z.Q
    return {"c": c, "Ca": Ca, "Cb": Cb, "T": T, "z": z, "rp_a": rp_a, "rp_x": rp_x}


def shift_scalar(pub, where):
    """Honest transcript with one scalar replaced by (value + Q): the same residue, a different encoding."""
    p = copy.deepcopy(pub)
    if where == "z":
        p["z"] += Z.Q
    else:
        key, i, k = where                      # e.g. ("rp_a", 5, 2): proof 5 of rp_a, tuple slot 2
        Bs, proofs = p[key]
        pr = list(proofs[i]); pr[k] += Z.Q; proofs[i] = tuple(pr)
    return p
