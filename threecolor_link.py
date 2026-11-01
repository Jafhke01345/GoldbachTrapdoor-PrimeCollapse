"""
threecolor_link.py - proves, in zero knowledge, that the Pedersen commitment Ca = g^a h^ra hides a PRIME a < 2^bits,
by linking the graph 3-colouring proof (zk_threecolor.py) to Ca.

Why zk_threecolor.py alone is not enough: its node colours sit behind SHA-256 commitments, and nothing ties the
hidden x in the colouring to the number inside Ca. Here the colours are PEDERSEN commitments instead, so the
link can be proved with group equations.

    Statement : Ca (and the public graph for "x is a prime below 2^bits")
    Witness   : a, ra, and a proper 3-colouring of the graph that encodes the bits of a

    1. Bit commitments B_i = g^{b_i} h^{r_i} with prod B_i^(2^i) == Ca, each proved to hide 0 or 1 by the
       Schnorr OR proof of zkrp_toy.py. So Ca hides sum b_i 2^i, an integer in [0, 2^bits).
    2. Each round the prover permutes the colours {0,1,2} by a random pi, and commits K_v = g^{pi(col v)} h^{s_v}
       for every node v. The Fiat-Shamir hash of EVERYTHING below picks one edge per round; the colours of
       its two ends are opened (colour, s). Same protocol and soundness as zk_threecolor.py: a round with a
       bad edge is caught with probability >= 1/|E|.
    3. The link, checked in EVERY round for every bit i. x_i is coloured pi(T) if b_i = 1 and pi(F) if b_i = 0, so
           E_i = K_{x_i}/K_F  =  D^{b_i} h^{rho_i}        with D = K_T/K_F.
       This is proved by a two-base Schnorr proof of knowledge of (b_i, r_i, rho_i) such that
           B_i = g^b h^r   and   E_i = D^b h^rho
       with ONE shared response for b_i. Binding of the Pedersen commitments (g and h have no known discrete-log
       relation) then forces  col(x_i) = col(T) when b_i = 1 and col(x_i) = col(F) when b_i = 0.
    The graph forces the colouring to be proper only if the committed bits are a prime.

Proof size and time grow with graph size times rounds (about 900 rounds for 3 bits). That is why real systems use
SNARKs instead of 3-colouring; this is a toy-size, honest bridge.

WHAT THIS IS NOT: toy 256-bit group, a few bits only, not constant-time, unaudited. Zero knowledge is argued
(honest-verifier simulation under the Fiat-Shamir model) and tested statistically, not machine-checked.

Run `python threecolor_link.py` for the adversarial self-test.
"""
import hashlib
import secrets
import sys

import zk_threecolor as TC
import zkrp_toy as Z

P, Q, G, H = Z.P, Z.Q, Z.G, Z.H
LAMBDA = TC.LAMBDA
MAX_ROUNDS = 5000


def _hash_int(*parts):
    data = b"|".join(str(p).encode() for p in parts)
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def _seed(g, Ca, bits, Bs, K, A):
    """Fiat-Shamir seed over the whole statement and every first message (shapes are validated before this)."""
    h = hashlib.sha256(b"3col-link|" + g.digest() + f"|{bits}|{Z.P}|{Z.G}|{Z.H}|{Ca}".encode())
    h.update(("|" + "|".join(str(b) for b in Bs)).encode())
    for rnd in K:
        h.update(("|K|" + "|".join(str(k) for k in rnd)).encode())
    for rnd in A:
        h.update(("|A|" + "|".join(f"{a1}|{a2}" for a1, a2 in rnd)).encode())
    return h.digest()


def _edge(seed, edges, r):
    d = hashlib.sha256(seed + b"edge" + r.to_bytes(4, "big")).digest()
    return edges[int.from_bytes(d, "big") % len(edges)]


def _e(seed, r, i):
    d = hashlib.sha256(seed + b"e" + r.to_bytes(4, "big") + i.to_bytes(2, "big")).digest()
    return int.from_bytes(d, "big") % Q


def _inv(x):
    return pow(x, -1, P)


def rounds_needed(g, lam=LAMBDA):
    return TC.rounds_needed(g, lam)


def prove(a, ra, bits=3, rounds=None, _colours=None, _bits=None, _link_bits=None):
    """Return a proof that Ca = commit(a, ra) hides a prime a < 2^bits.
    `_colours` / `_bits` / `_link_bits` are TEST HOOKS: they let the suite play a prover whose colouring or bit witness is
    wrong, or one that uses different bits in the Ca-side and the colouring-side equations."""
    g = TC.prime_graph(bits)
    if type(a) is not int or not (0 <= a < (1 << bits)):
        raise ValueError("a out of range")
    colours = _colours if _colours is not None else TC.witness_colouring(g, a, bits)
    bv = _bits if _bits is not None else [(a >> i) & 1 for i in range(bits)]
    lb = _link_bits if _link_bits is not None else bv      # bits used on the colouring side of the link
    Ca = Z.commit(a, ra)
    # --- bit commitments with sum r_i 2^i == ra, each proved to be a bit
    rs = [secrets.randbelow(Q) for _ in range(bits)]
    rs[0] = (ra - sum(rs[i] << i for i in range(1, bits))) % Q
    Bs = [Z.commit(bv[i], rs[i]) for i in range(bits)]
    tag = hashlib.sha256(f"{g.digest().hex()}|{bits}|{Ca}".encode()).hexdigest()[:32]
    bit_proofs = [Z.or_prove(Bs[i], bv[i], rs[i], f"link:{tag}:{i}") for i in range(bits)]

    rounds = rounds_needed(g) if rounds is None else rounds
    perms, svals, K, A, wit = [], [], [], [], []
    for _ in range(rounds):
        perm = [0, 1, 2]
        for i in (2, 1):
            j = secrets.randbelow(i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        s = [secrets.randbelow(Q) for _ in range(g.n)]
        Kr = [Z.commit(perm[colours[v]], s[v]) for v in range(g.n)]
        D = Kr[TC.T] * _inv(Kr[TC.F]) % P
        Ar, wr = [], []
        sD = (s[TC.T] - s[TC.F]) % Q
        for i in range(bits):
            xi = g.literals[i][0]
            rho = (s[xi] - s[TC.F] - lb[i] * sD) % Q
            k, u1, u2 = (secrets.randbelow(Q) for _ in range(3))
            Ar.append((pow(G, k, P) * pow(H, u1, P) % P, pow(D, k, P) * pow(H, u2, P) % P))
            wr.append((k, u1, u2, rho))
        perms.append(perm); svals.append(s); K.append(Kr); A.append(Ar); wit.append(wr)
    seed = _seed(g, Ca, bits, Bs, K, A)
    edges = sorted(g.edges)
    Z_, opens = [], []
    for r in range(rounds):
        zr = []
        for i in range(bits):
            e = _e(seed, r, i)
            k, u1, u2, rho = wit[r][i]
            zr.append(((k + e * lb[i]) % Q, (u1 + e * rs[i]) % Q, (u2 + e * rho) % Q))
        Z_.append(zr)
        u, v = _edge(seed, edges, r)
        opens.append((perms[r][colours[u]], svals[r][u], perms[r][colours[v]], svals[r][v]))
    return {"Ca": Ca, "B": Bs, "bit_proofs": bit_proofs, "K": K, "A": A, "z": Z_, "open": opens}


def verify(Ca, proof, bits=3, lam=LAMBDA):
    """Total function: anything malformed gives False."""
    try:
        return _verify(Ca, proof, bits, lam)
    except Exception:
        return False


def _verify(Ca, proof, bits, lam):
    if type(bits) is not int or not (1 <= bits <= 6) or not Z._element(Ca):
        return False
    if type(proof) is not dict or set(proof) != {"Ca", "B", "bit_proofs", "K", "A", "z", "open"}:
        return False
    if proof["Ca"] != Ca:
        return False
    g = TC.prime_graph(bits)
    Bs, bps, K, A, Zs, op = (proof[k] for k in ("B", "bit_proofs", "K", "A", "z", "open"))
    if any(type(x) is not list for x in (Bs, bps, K, A, Zs, op)):
        return False
    R = len(K)
    if not (rounds_needed(g, lam) <= R <= MAX_ROUNDS) or not (len(A) == len(Zs) == len(op) == R):
        return False
    if len(Bs) != bits or len(bps) != bits:
        return False
    # --- Ca is the recombination of the bit commitments, each of which hides a bit
    tag = hashlib.sha256(f"{g.digest().hex()}|{bits}|{Ca}".encode()).hexdigest()[:32]
    if not Z.range_verify(Ca, (Bs, bps), bits, f"link:{tag}"):
        return False
    # --- shapes and strict encodings
    for r in range(R):
        if type(K[r]) is not list or len(K[r]) != g.n or not all(Z._element(k) for k in K[r]):
            return False
        if type(A[r]) is not list or len(A[r]) != bits or type(Zs[r]) is not list or len(Zs[r]) != bits:
            return False
        for i in range(bits):
            if type(A[r][i]) not in (tuple, list) or len(A[r][i]) != 2 or not all(Z._element(v) for v in A[r][i]):
                return False
            if type(Zs[r][i]) not in (tuple, list) or len(Zs[r][i]) != 3 or not all(Z._scalar(v) for v in Zs[r][i]):
                return False
        if type(op[r]) not in (tuple, list) or len(op[r]) != 4:
            return False
    seed = _seed(g, Ca, bits, Bs, K, [[tuple(a) for a in ar] for ar in A])
    edges = sorted(g.edges)
    for r in range(R):
        Kr = K[r]
        D = Kr[TC.T] * _inv(Kr[TC.F]) % P
        for i in range(bits):
            xi = g.literals[i][0]
            E = Kr[xi] * _inv(Kr[TC.F]) % P
            e = _e(seed, r, i)
            zb, z1, z2 = Zs[r][i]
            A1, A2 = A[r][i]
            if pow(G, zb, P) * pow(H, z1, P) % P != A1 * pow(Bs[i], e, P) % P:
                return False
            if pow(D, zb, P) * pow(H, z2, P) % P != A2 * pow(E, e, P) % P:
                return False
        u, v = _edge(seed, edges, r)
        cu, su, cv, sv = op[r]
        if type(cu) is not int or type(cv) is not int or cu not in (0, 1, 2) or cv not in (0, 1, 2) or cu == cv:
            return False
        if not (Z._scalar(su) and Z._scalar(sv)):
            return False
        if Z.commit(cu, su) != Kr[u] or Z.commit(cv, sv) != Kr[v]:
            return False
    return True


# ============================================================================ self-test
def _selftest():
    import copy
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    bits = 3
    g = TC.prime_graph(bits)
    R = rounds_needed(g)
    print(f"graph: {g.n} nodes, {len(g.edges)} edges, {R} rounds\n")

    print("1) honest proofs")
    proofs = {}
    for a in (2, 3, 5, 7):
        ra = secrets.randbelow(Q)
        pr = prove(a, ra)
        proofs[a] = (ra, pr)
        check(f"a = {a} (prime): accepted", verify(Z.commit(a, ra), pr))

    print("\n2) non-primes cannot be proven honestly")
    for a in (0, 1, 4, 6):
        try:
            prove(a, secrets.randbelow(Q))
            check(f"a = {a}: honest prover refuses", False)
        except ValueError:
            check(f"a = {a}: honest prover refuses", True)

    print("\n3) the link: colouring and Ca must agree")
    ra = secrets.randbelow(Q)
    # colouring of the prime 5 (bits 1,0,1) while Ca commits to 4 (bits 0,0,1), proved with 4's bit witness
    col5 = TC.witness_colouring(g, 5, bits)
    bad = prove(4, ra, _colours=col5)
    check("Ca = commit(4) with the colouring of 5: rejected", verify(Z.commit(4, ra), bad), False)
    # same colouring and bit witness of 5, but presented against a different commitment
    ra5, pr5 = proofs[5]
    check("proof for commit(5) presented against commit(3): rejected", verify(Z.commit(3, ra5), pr5), False)
    check("proof for commit(5) presented against another opening of 5 (fresh randomness): rejected",
          verify(Z.commit(5, (ra5 + 1) % Q), pr5), False)
    # a cheater whose bits are exactly those of 4 (link consistent) but whose colouring is not proper:
    # the colouring of 5 with the literal x_0 / NOT x_0 swapped
    col4 = list(TC.witness_colouring(g, 5, bits))
    x0, nx0 = g.literals[0]
    col4[x0], col4[nx0] = col4[nx0], col4[x0]
    bad_edges = [e for e in g.edges if col4[e[0]] == col4[e[1]]]
    check("the cheating colouring has at least one violated edge", len(bad_edges) >= 1)
    bad = prove(4, ra, _colours=col4)
    check("a = 4 with a colouring that has a violated edge: rejected", verify(Z.commit(4, ra), bad), False)
    # the split cheater: Ca-side equation uses the bits of 4, colouring-side equation uses the bits of 5 and the
    # proper colouring of 5. Only the SHARED response z_b can expose this (needs both equations to hold).
    split = prove(4, ra, _colours=col5, _link_bits=[(5 >> i) & 1 for i in range(bits)])
    check("split cheater (Ca = 4, colouring and link bits of 5): rejected", verify(Z.commit(4, ra), split), False)
    few = prove(5, ra, rounds=3)
    check("an honest prover with too few rounds is rejected at the default soundness level", verify(Z.commit(5, ra), few), False)

    print("\n4) every single field of an honest proof is tied down")
    ra, pr = proofs[5]
    Ca = Z.commit(5, ra)

    def mutate(label, fn):
        p = copy.deepcopy(pr)
        fn(p)
        check(f"{label}: rejected", verify(Ca, p), False)

    mutate("B[0] replaced", lambda p: p["B"].__setitem__(0, p["B"][1]))
    mutate("bit proof swapped", lambda p: p["bit_proofs"].__setitem__(0, p["bit_proofs"][1]))
    mutate("K of a node replaced", lambda p: p["K"][0].__setitem__(5, p["K"][0][6]))
    mutate("K of the T node replaced", lambda p: p["K"][3].__setitem__(0, p["K"][3][1]))
    mutate("A pair replaced", lambda p: p["A"][7].__setitem__(1, (p["A"][7][1][1], p["A"][7][1][1])))
    def bump(p, r, i, k, delta, wrap=True):
        z = list(p["z"][r][i])
        z[k] = (z[k] + delta) % Q if wrap else z[k] + delta
        p["z"][r][i] = tuple(z)

    mutate("z_b + 1", lambda p: bump(p, 2, 0, 0, 1))
    mutate("z_b + Q (non-canonical encoding)", lambda p: bump(p, 2, 0, 0, Q, wrap=False))
    mutate("z_rho + 1", lambda p: bump(p, 9, 2, 2, 1))
    mutate("opened colour changed", lambda p: p["open"].__setitem__(4, (p["open"][4][2], p["open"][4][1], p["open"][4][0], p["open"][4][3])))
    mutate("opened blinding + 1", lambda p: p["open"].__setitem__(4, (p["open"][4][0], (p["open"][4][1] + 1) % Q, p["open"][4][2], p["open"][4][3])))
    mutate("one round dropped", lambda p: [p[k].pop() for k in ("K", "A", "z", "open")])
    mutate("rounds below the soundness minimum", lambda p: [p[k].__delitem__(slice(R // 2, None)) for k in ("K", "A", "z", "open")])
    mutate("K negated (outside the subgroup)", lambda p: p["K"][0].__setitem__(5, P - p["K"][0][5]))
    mutate("unknown extra key", lambda p: p.__setitem__("extra", 1))
    check("None rejected", verify(Ca, None), False)
    check("empty dict rejected", verify(Ca, {}), False)

    print("\n4b) the Fiat-Shamir seed covers every input (an adaptive cheater needs this to fail)")
    g3 = TC.prime_graph(bits)
    base = dict(g=g3, Ca=Ca, bits=bits, Bs=list(pr["B"]), K=copy.deepcopy(pr["K"]),
                A=[[tuple(a) for a in ar] for ar in pr["A"]])
    s0 = _seed(**base)
    def changed(**kw):
        return _seed(**{**base, **kw}) != s0
    K2 = copy.deepcopy(pr["K"]); K2[1][2] = pr["K"][1][3]
    A2 = [list(ar) for ar in base["A"]]; A2[1][0] = (A2[1][0][1], A2[1][0][0])
    check("seed changes when a K commitment changes", changed(K=K2))
    check("seed changes when a first message A changes", changed(A=A2))
    check("seed changes when Ca changes", changed(Ca=Z.commit(5, (ra + 1) % Q)))
    check("seed changes when a bit commitment B changes", changed(Bs=[pr["B"][1]] + list(pr["B"][1:])))
    check("seed changes with the bit width", changed(bits=bits + 1, g=TC.prime_graph(bits + 1)))

    print("\n5) soundness comes from the number of rounds")
    nb = len(bad_edges)
    lam1 = 0.2
    r1 = rounds_needed(g, lam1)
    trials, passed = 30, 0
    for _ in range(trials):
        ra_c = secrets.randbelow(Q)
        pc = prove(4, ra_c, rounds=r1, _colours=col4)
        passed += verify(Z.commit(4, ra_c), pc, lam=lam1)
    exp = (1 - nb / len(g.edges)) ** r1
    print(f"    {nb} violated edge(s), {r1} rounds (lambda={lam1}): cheater passed {passed}/{trials}, expected about {exp:.2f}")
    check("with too few rounds the cheater passes about as often as predicted (so the round count is what protects)",
          abs(passed / trials - exp) < 0.35 and passed > 0)
    check("with the full round count the same cheater never passes", verify(Z.commit(4, ra), bad), False)

    print("\n6) statistical zero knowledge of the opened colours")
    counts = {}
    for _ in range(6):
        pr = prove(5, secrets.randbelow(Q), rounds=600)
        for cu, su, cv, sv in pr["open"]:
            counts[(cu, cv)] = counts.get((cu, cv), 0) + 1
    total = sum(counts.values())
    expected = total / 6
    chi2 = sum((counts.get(k, 0) - expected) ** 2 / expected for k in [(a, b) for a in range(3) for b in range(3) if a != b])
    print(f"    ordered pairs seen: {sorted(counts.items())}, chi2 = {chi2:.1f} (df 5, 99.9% limit 20.5)")
    check("opened ordered pairs are uniform over the 6 distinct pairs", chi2 < 20.5 and len(counts) == 6)

    print("\n7) the link composes with the midpoint proof")
    w = {}
    pub = Z.prove(5, 9, _witness=w)
    link = prove(5, w["ra"])
    check("the Ca published by the Goldbach/midpoint proof is the Ca the prime link accepts",
          (Z.verify(pub), verify(pub["Ca"], link)), (True, True))
    pub2 = Z.prove(4, 10, _witness=w)
    check("a non-prime a cannot reuse that link (different Ca)", verify(pub2["Ca"], link), False)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy 256-bit group, a few bits only, zero knowledge argued not proven, unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
