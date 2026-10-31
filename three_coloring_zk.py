"""
three_coloring_zk.py - the classic zero-knowledge proof that a graph is 3-colorable
(Goldreich-Micali-Wigderson), made non-interactive with Fiat-Shamir. Commitments and openings are hex.

    statement : a public graph G
    witness   : a proper 3-coloring of G (hidden)
    one round : the prover randomly permutes the three colors, commits to every node's permuted color
                (SHA-256 with a fresh 16-byte nonce, printed as hex), the challenge picks one edge, and the
                prover opens only its two endpoints. The verifier checks the commitments match and the two
                colors differ. A cheater with a bad edge is caught with probability 1/|E| per round, so the
                proof repeats ceil(bits * ln2 / -ln(1 - 1/|E|)) independent rounds (about 2^-bits error).
    FS        : the edge of round i is derived from a hash of the graph and ALL commitments of ALL rounds.

WHAT THIS IS NOT
    A standalone, educational component. It is not connected to the other proofs in this repo and does not
    strengthen them. Hash commitments here are computationally hiding and binding (SHA-256, random-oracle
    model for Fiat-Shamir). Toy, unaudited.

Run `python three_coloring_zk.py` for the adversarial self-test.
"""
import hashlib
import math
import os
import random
import sys
from typing import List, Optional, Sequence, Tuple

NONCE_BYTES = 16


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


class Graph:
    def __init__(self, n: int, edges: Sequence[Tuple[int, int]]):
        if type(n) is not int or n < 2 or n > 10000:
            raise ValueError("bad node count")
        seen = set()
        for e in edges:
            if len(e) != 2 or any(type(x) is not int or not (0 <= x < n) for x in e) or e[0] == e[1]:
                raise ValueError("bad edge")
            seen.add((min(e), max(e)))
        if not seen:
            raise ValueError("a graph needs at least one edge")
        self.n, self.edges = n, tuple(sorted(seen))

    def digest(self) -> bytes:
        return _h(b"3col-graph", self.n.to_bytes(4, "big"), *[u.to_bytes(4, "big") + v.to_bytes(4, "big") for u, v in self.edges])


def commit(round_i: int, node: int, color: int, nonce: bytes) -> str:
    return _h(b"3col-commit", round_i.to_bytes(4, "big"), node.to_bytes(4, "big"), bytes([color]), nonce).hex()


def min_rounds(m: int, bits: int = 40) -> int:
    """Rounds needed so a cheater with one bad edge succeeds with probability <= 2^-bits."""
    if m == 1:
        return bits
    return math.ceil(bits * math.log(2) / -math.log(1 - 1 / m))


def _challenge_edges(graph: Graph, commitments: List[List[str]]) -> List[int]:
    seed = _h(b"3col-fs", graph.digest(), *[c.encode() for rnd in commitments for c in rnd])
    return [int.from_bytes(_h(b"3col-edge", seed, i.to_bytes(4, "big")), "big") % len(graph.edges) for i in range(len(commitments))]


def is_proper(graph: Graph, coloring: Sequence[int]) -> bool:
    return (len(coloring) == graph.n and all(type(c) is int and 0 <= c <= 2 for c in coloring)
            and all(coloring[u] != coloring[v] for u, v in graph.edges))


def _prove(graph: Graph, coloring: Sequence[int], rounds: int, rng: Optional[random.Random] = None) -> dict:
    """Prover without the honesty check (test hook: lets tests drive a cheating prover)."""
    rnd = rng or random.SystemRandom()
    all_commit, all_secret = [], []
    for i in range(rounds):
        perm = [0, 1, 2]
        rnd.shuffle(perm)
        cols = [perm[c] if c < 3 else c for c in coloring]          # colors above 2 only occur for cheating tests
        nonces = [os.urandom(NONCE_BYTES) for _ in range(graph.n)]
        all_commit.append([commit(i, v, cols[v], nonces[v]) for v in range(graph.n)])
        all_secret.append((cols, nonces))
    openings = []
    for i, e in enumerate(_challenge_edges(graph, all_commit)):
        u, v = graph.edges[e]
        cols, nonces = all_secret[i]
        openings.append({"cu": cols[u], "cv": cols[v], "nu": nonces[u].hex(), "nv": nonces[v].hex()})
    return {"rounds": rounds, "commitments": all_commit, "openings": openings}


def prove(graph: Graph, coloring: Sequence[int], soundness_bits: int = 40) -> dict:
    if not is_proper(graph, coloring):
        raise ValueError("not a proper 3-coloring")
    return _prove(graph, coloring, min_rounds(len(graph.edges), soundness_bits))


def _verify(graph: Graph, proof: dict, need_rounds: int) -> bool:
    k, commitments, openings = proof["rounds"], proof["commitments"], proof["openings"]
    if type(k) is not int or k < need_rounds or len(commitments) != k or len(openings) != k:
        return False
    for rnd in commitments:
        if len(rnd) != graph.n or any(type(c) is not str or len(c) != 64 or any(ch not in "0123456789abcdef" for ch in c) for c in rnd):
            return False
    for i, e in enumerate(_challenge_edges(graph, commitments)):
        u, v = graph.edges[e]
        o = openings[i]
        cu, cv = o["cu"], o["cv"]
        if type(cu) is not int or type(cv) is not int or not (0 <= cu <= 2) or not (0 <= cv <= 2) or cu == cv:
            return False
        nu, nv = bytes.fromhex(o["nu"]), bytes.fromhex(o["nv"])
        if len(nu) != NONCE_BYTES or len(nv) != NONCE_BYTES:
            return False
        if commit(i, u, cu, nu) != commitments[i][u] or commit(i, v, cv, nv) != commitments[i][v]:
            return False
    return True


def verify(graph: Graph, proof: dict, soundness_bits: int = 40) -> bool:
    """Total function: malformed input yields False, never an exception."""
    try:
        return _verify(graph, proof, min_rounds(len(graph.edges), soundness_bits))
    except Exception:
        return False


# ============================================================================ self-test
def _petersen() -> Tuple[Graph, List[int]]:
    outer = [(i, (i + 1) % 5) for i in range(5)]
    inner = [(5 + i, 5 + (i + 2) % 5) for i in range(5)]
    spokes = [(i, 5 + i) for i in range(5)]
    g = Graph(10, outer + inner + spokes)
    # a proper 3-coloring found by greedy search
    col = [-1] * 10
    for v in range(10):
        used = {col[w if u == v else u] for (u, w) in g.edges if v in (u, w)} - {-1}
        col[v] = min(c for c in range(3) if c not in used)
    assert is_proper(g, col)
    return g, col


def _selftest() -> int:
    failures = []

    def expect(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    g, col = _petersen()
    k = min_rounds(len(g.edges))
    print(f"graph: Petersen, {g.n} nodes, {len(g.edges)} edges, {k} rounds for 2^-40")

    print("1) honest proofs")
    proof = prove(g, col)
    expect("honest proof accepted", verify(g, proof))
    expect("every printed commitment is 64 hex characters", all(len(c) == 64 for r in proof["commitments"] for c in r))
    c6 = Graph(6, [(i, (i + 1) % 6) for i in range(6)])
    expect("even cycle (2-colorable, so also 3-colorable) accepted", verify(c6, prove(c6, [0, 1, 0, 1, 0, 1])))

    print("\n2) zero-knowledge shape")
    seen = set()
    for r in proof["openings"]:
        seen.add((r["cu"], r["cv"]))
    expect("openings reveal only a pair of distinct permuted colors per round", all(a != b for a, b in seen))
    expect("across rounds the same node is opened with different colors (fresh permutation)", len({(r["cu"], r["cv"]) for r in proof["openings"]}) > 1)
    expect("the commitments of two proofs for the same coloring differ", prove(g, col)["commitments"] != proof["commitments"])
    expect("the prover refuses to prove an improper coloring", _raises(lambda: prove(g, [0] * 10)))

    print("\n3) tampering")
    def mut(f):
        p = {"rounds": proof["rounds"], "commitments": [list(r) for r in proof["commitments"]], "openings": [dict(o) for o in proof["openings"]]}
        f(p)
        return verify(g, p)
    expect("one commitment changed", mut(lambda p: p["commitments"][0].__setitem__(0, "0" * 64)), False)
    expect("an opened color changed", mut(lambda p: p["openings"][3].__setitem__("cu", (p["openings"][3]["cu"] + 1) % 3)), False)
    expect("an opened nonce changed", mut(lambda p: p["openings"][3].__setitem__("nv", "00" * NONCE_BYTES)), False)
    expect("both endpoints opened with the same color", mut(lambda p: p["openings"][5].__setitem__("cv", p["openings"][5]["cu"])), False)
    expect("color outside {0,1,2}", mut(lambda p: p["openings"][2].__setitem__("cu", 3)), False)
    expect("rounds reordered (challenges no longer match)", mut(lambda p: (p["commitments"].reverse(), p["openings"].reverse())), False)
    expect("fewer rounds than required", verify(g, {"rounds": 5, "commitments": proof["commitments"][:5], "openings": proof["openings"][:5]}), False)
    expect("proof for a different graph", verify(c6, proof), False)
    two = Graph(2, [(0, 1)])
    pairs = {(r["cu"], r["cv"]) for r in _prove(two, [0, 1], 120)["openings"]}
    expect("hiding: one fixed edge opened 120 times shows every ordered pair of distinct colors (the permutation hides the coloring)", len(pairs), 6)
    expect("junk input never raises", all(verify(g, x) is False for x in (None, {}, {"rounds": "x"}, [], 7)))

    print("\n4) soundness against a cheating prover")
    k4 = Graph(4, [(a, b) for a in range(4) for b in range(a + 1, 4)])      # K4 is NOT 3-colorable
    bad = [0, 1, 2, 2]                                                      # exactly one monochromatic edge of 6
    forged = 0
    for _ in range(100):
        if verify(k4, _prove(k4, bad, min_rounds(6))):
            forged += 1
    expect("100 full-length cheating proofs for K4 are all rejected", forged, 0)
    k4_four = [0, 1, 2, 3]                                                  # a proper 4-coloring: needs a fourth color
    expect("a prover that uses a fourth color is rejected", verify(k4, _prove(k4, k4_four, min_rounds(6))), False)
    expect("a short but honestly generated proof (5 rounds) is rejected", verify(g, _prove(g, col, 5)), False)
    trials, accepted, kk = 1500, 0, 3
    for _ in range(trials):
        if _verify(k4, _prove(k4, bad, kk), kk):
            accepted += 1
    rate, want = accepted / trials, (5 / 6) ** kk
    expect(f"with {kk} rounds a cheater passes at the predicted rate (measured {rate:.3f}, expected {want:.3f})", abs(rate - want) < 0.06)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: standalone educational component. Toy, unaudited.")
    return 1 if failures else 0


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except ValueError:
        return True


if __name__ == "__main__":
    sys.exit(_selftest())
