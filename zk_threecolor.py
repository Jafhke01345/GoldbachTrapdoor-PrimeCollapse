"""
zk_threecolor.py - zero-knowledge proof that a hidden small number is prime, through graph 3-colouring.

    Statement   (public)  : a graph G built from the formula "x is a prime below 2^bits"
    Witness     (private) : x, expanded into a proper 3-colouring of G
    Proof                 : the Goldreich-Micali-Wigderson protocol, made non-interactive with Fiat-Shamir.
                            Each round the prover randomly permutes the three colours, commits to every
                            node's colour (SHA-256 of colour || nonce, printed as hex), and opens only the two
                            ends of ONE edge chosen by the hash of all commitments.
    Soundness             : a colouring with at least one bad edge is caught in a round with probability
                            >= 1/|E|, so rounds = ceil(lambda * ln 2 * |E|) gives cheating probability <= 2^-lambda.
    Zero knowledge        : the two opened colours are a uniformly random ordered pair of distinct colours,
                            whatever the witness; the test suite checks that statistically.

The formula is in CNF: one clause "x != q" for every non-prime q below 2^bits, each clause an OR of `bits`
literals. OR gates use the standard 3-node gadget, and each clause output is forced to the colour TRUE.

WHAT THIS IS NOT
    * Not linked to the Pedersen commitments Ca, Cb of the rest of this repository: nothing here proves that
      the x in the proof is the same number as the one committed in Ca. Building that bridge is open work.
    * Only tiny numbers (default 3 bits, i.e. primes below 8): the proof size grows with graph size times
      rounds, which is why real systems do not use 3-colouring.
    * Hex is only the printed form of the commitments. It adds no security.
    * Toy, unaudited, not constant-time.

Run `python zk_threecolor.py` for the adversarial self-test.
"""
import hashlib
import math
import secrets
import sys
from itertools import product
from typing import Dict, List, Optional, Tuple

T, F, B = 0, 1, 2            # canonical colours of the three base nodes (a triangle)
LAMBDA = 20                  # default soundness parameter (cheating probability 2^-LAMBDA)
MAX_NODES = 5000
MAX_ROUNDS = 200000


# ============================================================================ graph construction
class Graph:
    def __init__(self):
        self.n = 3
        self.edges = set()
        self.adj: Dict[int, set] = {0: set(), 1: set(), 2: set()}
        self.literals: Dict[int, Tuple[int, int]] = {}          # bit index -> (node of x_i, node of NOT x_i)
        for u, v in ((0, 1), (1, 2), (0, 2)):
            self.edge(u, v)

    def node(self) -> int:
        i = self.n
        self.n += 1
        self.adj[i] = set()
        return i

    def edge(self, u: int, v: int):
        self.edges.add((min(u, v), max(u, v)))
        self.adj[u].add(v)
        self.adj[v].add(u)

    def variable(self, idx: int):
        x, nx = self.node(), self.node()
        self.edge(x, nx); self.edge(x, B); self.edge(nx, B)       # {x, nx} take the colours {T, F}, opposite
        self.literals[idx] = (x, nx)
        return x, nx

    def or_gate(self, a: int, b: int) -> int:
        """One-sided OR gadget. Output w can be coloured T only if a or b is T (and F is possible otherwise)."""
        u, v, w = self.node(), self.node(), self.node()
        for p, q in ((a, u), (b, v), (u, v), (u, w), (v, w), (w, B)):
            self.edge(p, q)
        return w

    def assert_true(self, node: int):
        self.edge(node, F)                                        # with the edge to B already present: node = T

    def digest(self) -> bytes:
        h = hashlib.sha256(b"3col-graph" + self.n.to_bytes(4, "big"))
        for u, v in sorted(self.edges):
            h.update(u.to_bytes(4, "big") + v.to_bytes(4, "big"))
        return h.digest()


def primes_below(limit: int) -> List[int]:
    return [p for p in range(2, limit) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def prime_graph(bits: int = 3) -> Graph:
    """Graph that is 3-colourable exactly when some x in [0, 2^bits) is prime: AND over every non-prime q of
    the clause (x != q), each clause being the OR of the bits.. flipped to disagree with q in some position."""
    if type(bits) is not int or not (1 <= bits <= 6):
        raise ValueError("bits must be in 1..6")
    g = Graph()
    for i in range(bits):
        g.variable(i)
    pr = set(primes_below(1 << bits))
    for q in range(1 << bits):
        if q in pr:
            continue
        # x != q  <=>  some bit i has x_i != q_i  <=>  OR over i of (x_i if q_i == 0 else NOT x_i)
        lits = [g.literals[i][0] if not (q >> i) & 1 else g.literals[i][1] for i in range(bits)]
        out = lits[0]
        for lit in lits[1:]:
            out = g.or_gate(out, lit)
        g.assert_true(out)
    return g


# ============================================================================ witness colouring
def is_proper(g: Graph, colours: List[int]) -> bool:
    return len(colours) == g.n and all(c in (0, 1, 2) for c in colours) and all(colours[u] != colours[v] for u, v in g.edges)


def witness_colouring(g: Graph, x: int, bits: int) -> List[int]:
    """Colour the graph for the assignment x. Raises ValueError if x is not a prime (no proper colouring exists)."""
    colours: List[Optional[int]] = [None] * g.n
    colours[0], colours[1], colours[2] = T, F, B
    for i in range(bits):
        xi, nxi = g.literals[i]
        colours[xi], colours[nxi] = ((T, F) if (x >> i) & 1 else (F, T))
    order = [i for i in range(g.n) if colours[i] is None]

    def ok(i, c):
        return all(colours[j] != c for j in g.adj[i] if colours[j] is not None)

    def solve(k):
        if k == len(order):
            return True
        i = order[k]
        for c in (T, F, B):
            if ok(i, c):
                colours[i] = c
                if solve(k + 1):
                    return True
                colours[i] = None
        return False

    for i in range(g.n):                                          # the fixed part must itself be consistent
        for j in g.adj[i]:
            if colours[i] is not None and colours[j] is not None and colours[i] == colours[j]:
                raise ValueError("x is not a prime below 2^bits")
    if not solve(0):
        raise ValueError("x is not a prime below 2^bits")
    return colours  # type: ignore[return-value]


# ============================================================================ the proof
def _commit(colour: int, nonce: bytes) -> str:
    return hashlib.sha256(b"3col-commit" + bytes([colour]) + nonce).hexdigest()


def rounds_needed(g: Graph, lam: int = LAMBDA) -> int:
    return math.ceil(lam * math.log(2) * len(g.edges))


def _challenges(g: Graph, commitments: List[List[str]]) -> List[Tuple[int, int]]:
    edges = sorted(g.edges)
    h = hashlib.sha256(b"3col-challenge" + g.digest())
    for rnd in commitments:
        h.update(b"".join(bytes.fromhex(c) for c in rnd))
    seed = h.digest()
    out = []
    for r in range(len(commitments)):
        d = hashlib.sha256(seed + r.to_bytes(4, "big")).digest()
        out.append(edges[int.from_bytes(d, "big") % len(edges)])
    return out


def prove(g: Graph, colours: List[int], rounds: Optional[int] = None, _allow_invalid: bool = False) -> dict:
    """Non-interactive proof that `colours` is a proper 3-colouring of g. `_allow_invalid` is a TEST HOOK that
    lets the suite play a cheating prover."""
    if not _allow_invalid and not is_proper(g, colours):
        raise ValueError("not a proper 3-colouring")
    rounds = rounds_needed(g) if rounds is None else rounds
    perms, nonces, commitments = [], [], []
    for _ in range(rounds):
        perm = [0, 1, 2]
        for i in (2, 1):                                          # Fisher-Yates with secrets
            j = secrets.randbelow(i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        ns = [secrets.token_bytes(32) for _ in range(g.n)]
        perms.append(perm); nonces.append(ns)
        commitments.append([_commit(perm[colours[i]], ns[i]) for i in range(g.n)])
    chal = _challenges(g, commitments)
    openings = []
    for r, (u, v) in enumerate(chal):
        openings.append((perms[r][colours[u]], nonces[r][u].hex(), perms[r][colours[v]], nonces[r][v].hex()))
    return {"commitments": commitments, "openings": openings}


def verify(g: Graph, proof, lam: int = LAMBDA) -> bool:
    """Total function: malformed input gives False, never an exception."""
    try:
        return _verify(g, proof, lam)
    except Exception:
        return False


def _verify(g: Graph, proof, lam: int) -> bool:
    if type(proof) is not dict or set(proof) != {"commitments", "openings"}:
        return False
    com, op = proof["commitments"], proof["openings"]
    if type(com) is not list or type(op) is not list or len(com) != len(op):
        return False
    if len(com) < rounds_needed(g, lam) or len(com) > MAX_ROUNDS or g.n > MAX_NODES:
        return False
    for rnd in com:
        if type(rnd) is not list or len(rnd) != g.n:
            return False
        for c in rnd:
            if type(c) is not str or len(c) != 64:
                return False
            bytes.fromhex(c)
    chal = _challenges(g, com)
    for r, (u, v) in enumerate(chal):
        o = op[r]
        if type(o) is not tuple and type(o) is not list:
            return False
        cu, nu, cv, nv = o
        if cu not in (0, 1, 2) or cv not in (0, 1, 2) or type(cu) is not int or type(cv) is not int or cu == cv:
            return False
        if type(nu) is not str or type(nv) is not str or len(nu) != 64 or len(nv) != 64:
            return False
        if _commit(cu, bytes.fromhex(nu)) != com[r][u] or _commit(cv, bytes.fromhex(nv)) != com[r][v]:
            return False
    return True


def to_hex(proof: dict) -> str:
    """Printable hex form of a proof: all commitments in order (the openings follow as colour||nonce)."""
    parts = [c for rnd in proof["commitments"] for c in rnd]
    for cu, nu, cv, nv in proof["openings"]:
        parts += [f"{cu:02x}{nu}", f"{cv:02x}{nv}"]
    return "".join(parts)


# ============================================================================ self-test
def _selftest() -> int:
    import copy
    failures = []

    def expect(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    bits = 3
    g = prime_graph(bits)
    R = rounds_needed(g)
    print(f"graph: {g.n} nodes, {len(g.edges)} edges; {R} rounds for 2^-{LAMBDA} soundness")

    print("\n1) the graph encodes primality")
    gate_ok = True
    for x in range(1 << bits):
        try:
            col = witness_colouring(g, x, bits)
            colourable = is_proper(g, col)
        except ValueError:
            colourable = False
        gate_ok &= colourable == (x in primes_below(1 << bits))
    expect("a proper colouring exists exactly for the primes below 8", gate_ok)
    g4 = prime_graph(4)
    expect("same for 4 bits (primes below 16)",
           all((lambda x: (lambda: (is_proper(g4, witness_colouring(g4, x, 4)) if x in primes_below(16) else True))())(x) for x in primes_below(16))
           and all(_raises(lambda x=x: witness_colouring(g4, x, 4)) for x in range(16) if x not in primes_below(16)))

    print("\n2) honest proofs")
    for x in (2, 3, 5, 7):
        p = prove(g, witness_colouring(g, x, bits))
        expect(f"x = {x}: accepted", verify(g, p))
    proof = prove(g, witness_colouring(g, 5, bits))
    h = to_hex(proof)
    expect(f"proof is plain hex ({len(h) // 2 // 1024} KiB)", all(ch in "0123456789abcdef" for ch in h))

    print("\n3) a cheating prover (x = 6, not prime) is caught")
    cheat = list(witness_colouring(g, 7, bits))
    xi, nxi = g.literals[0]
    cheat[xi], cheat[nxi] = F, T                                    # flip x0: 7 -> 6, gadgets left unfixed
    expect("the cheating colouring really is improper", is_proper(g, cheat), False)
    expect("honest prover refuses it", _raises(lambda: prove(g, cheat)))
    expect("cheating proof rejected at the full round count", verify(g, prove(g, cheat, _allow_invalid=True)), False)
    expect("a cheater using too few rounds is rejected", verify(g, prove(g, witness_colouring(g, 5, bits), rounds=R // 4)), False)
    cheat2 = [0] * g.n
    expect("all-one-colour 'proof'", verify(g, prove(g, cheat2, _allow_invalid=True)), False)

    print("\n4) tampering")
    base = prove(g, witness_colouring(g, 5, bits))
    p = copy.deepcopy(base); c = p["commitments"][0][5]; p["commitments"][0][5] = ("0" if c[0] != "0" else "1") + c[1:]
    expect("one commitment changed (hash challenge changes too)", verify(g, p), False)
    p = copy.deepcopy(base); cu, nu, cv, nv = p["openings"][0]; p["openings"][0] = ((cu + 1) % 3, nu, cv, nv)
    expect("opened colour changed", verify(g, p), False)
    p = copy.deepcopy(base); cu, nu, cv, nv = p["openings"][0]; p["openings"][0] = (cu, nu, cu, nu)
    expect("both ends opened as the same colour", verify(g, p), False)
    p = copy.deepcopy(base); p["openings"][0], p["openings"][1] = p["openings"][1], p["openings"][0]
    expect("openings of two rounds swapped", verify(g, p), False)
    p = copy.deepcopy(base); p["openings"][3] = p["openings"][3][:1] + ("00" * 32,) + p["openings"][3][2:]
    expect("wrong nonce", verify(g, p), False)
    expect("proof for the 3-bit graph does not verify against the 4-bit graph", verify(g4, base), False)
    expect("a proof for a different graph size", verify(prime_graph(2), base), False)

    print("\n5) hostile input never raises")
    for name, arg in (("None", None), ("list", []), ("missing key", {"commitments": []}), ("wrong types", {"commitments": "x", "openings": 1}),
                      ("short hex", {"commitments": [["ab"] * g.n] * R, "openings": [(0, "a" * 64, 1, "b" * 64)] * R})):
        expect(name, verify(g, arg), False)

    print("\n6) zero knowledge: the opened pair is a uniformly random pair of distinct colours")
    counts = {pair: 0 for pair in product(range(3), repeat=2) if pair[0] != pair[1]}
    samples = 0
    while samples < 12000:
        pr = prove(g, witness_colouring(g, 7, bits), rounds=R)
        for cu, _, cv, _ in pr["openings"]:
            counts[(cu, cv)] += 1; samples += 1
    exp = samples / 6
    worst = max(abs(v - exp) / exp for v in counts.values())
    expect(f"each of the 6 ordered pairs within 15% of uniform (worst deviation {worst:.1%})", worst < 0.15)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: demo of the mechanism, tiny numbers, NOT linked to the Pedersen commitments, toy, unaudited.")
    return 1 if failures else 0


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except ValueError:
        return True


if __name__ == "__main__":
    sys.exit(_selftest())
