"""
stark_core.py - a small, transparent (hash-based) STARK: algebraic intermediate representation (AIR),
DEEP composition and FRI, over the 252-bit prime field p = 2^251 + 17 * 2^192 + 1. Pure Python, only SHA-256 and field arithmetic.

    Statement  : "there is a trace (a table of field elements) that satisfies the AIR's transition
                  constraints on every pair of consecutive real rows and its boundary constraints"
    Proof      : Merkle roots of the low-degree extension of the trace and of the constraint quotient pieces, the
                  trace and quotient values at one out-of-domain point, a FRI proof that the DEEP combination is a
                  polynomial of degree < N, and QUERIES openings.
    No trusted setup, no pairings, no discrete logarithms: security rests on the collision resistance of SHA-256
    and on the FRI soundness conjecture (the same assumption family as production STARKs).

Parameters (conservative-looking, NOT a proven bound): blowup 8, 40 queries, 252-bit field. Soundness error is
about (1/2)^(3*40) under the usual conjecture for FRI with rate 1/8, plus a term of about
(degree / field size) from the out-of-domain point.

Zero knowledge: the trace is padded with random rows (at least 2*QUERIES + 2) so that the evaluations the proof
reveals (two row openings per query plus the two out-of-domain values per column) are masked by fresh
randomness. This is the standard randomised-trace argument; it is NOT machine-checked here. Treat it as honest-
verifier statistical hiding that is argued, not proven.

Educational toy: unaudited, not constant-time, Python big integers.

Run `python stark_core.py` for the adversarial self-test (honest proofs, cheating provers, every-field mutations).
"""
import hashlib
import secrets
import sys

K2 = 192                                    # P - 1 = C * 2^K2
C = (1 << 59) + 17
P = C * (1 << K2) + 1                        # 2^251 + 17 * 2^192 + 1, the field of the Stark elliptic curve
GEN = pow(3, C, P)                           # 3 generates the multiplicative group, so this has order exactly 2^K2
EL = 32                                     # bytes per field element
BLOWUP = 8
QUERIES = 40
FINAL_DEG = 8
PAD = 2 * QUERIES + 2                       # minimum random rows
COSET = 3


class ProverError(Exception):
    """The supplied trace does not satisfy the AIR (an honest prover cannot continue)."""


# ============================================================================ field and FFT
def inv(x):
    return pow(x, -1, P)


def batch_inv(xs):
    """Montgomery's trick. All entries must be nonzero."""
    acc, pre = 1, []
    for x in xs:
        pre.append(acc)
        acc = acc * x % P
    t = pow(acc, -1, P)
    out = [0] * len(xs)
    for i in range(len(xs) - 1, -1, -1):
        out[i] = t * pre[i] % P
        t = t * xs[i] % P
    return out


def horner(coeffs, x):
    r = 0
    for a in reversed(coeffs):
        r = (r * x + a) % P
    return r


def _root(n):
    return pow(GEN, (1 << K2) // n, P)


_TW = {}


def _twiddles(length, inverse):
    key = (length, inverse)
    if key not in _TW:
        w = pow(GEN, (1 << K2) // length, P)
        if inverse:
            w = pow(w, -1, P)
        half = length // 2
        tw = [1] * half
        for i in range(1, half):
            tw[i] = tw[i - 1] * w % P
        _TW[key] = tw
    return _TW[key]


def ntt(a, inverse=False):
    """Evaluations at w^i from coefficients (or the inverse). len(a) must be a power of two."""
    a = list(a)
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    length = 2
    while length <= n:
        half = length // 2
        tw = _twiddles(length, inverse)
        step = n // length
        for s in range(0, n, length):
            for k in range(half):
                u = a[s + k]
                v = a[s + k + half] * tw[k] % P
                a[s + k] = (u + v) % P
                a[s + k + half] = (u - v) % P
        length *= 2
    if inverse:
        ni = pow(n, -1, P)
        a = [x * ni % P for x in a]
    return a


def coset_eval(coeffs, n, shift=COSET):
    """Evaluate a polynomial (coefficient list, len <= n) on shift * <w_n>."""
    c = list(coeffs) + [0] * (n - len(coeffs))
    s = 1
    for i in range(n):
        c[i] = c[i] * s % P
        s = s * shift % P
    return ntt(c)


def coset_interp(vals, shift=COSET):
    c = ntt(vals, inverse=True)
    si = pow(shift, -1, P)
    s = 1
    for i in range(len(c)):
        c[i] = c[i] * s % P
        s = s * si % P
    return c


# ============================================================================ hashing
def _sha(b):
    return hashlib.sha256(b).digest()


def _enc(x):
    return x.to_bytes(EL, "big")


def _is_el(x):
    return type(x) is int and 0 <= x < P


class Transcript:
    def __init__(self, label):
        self.h = _sha(b"stark_core|" + label)

    def absorb(self, data):
        self.h = _sha(self.h + data)

    def absorb_els(self, els):
        self.absorb(b"".join(_enc(x) for x in els))

    def field(self):
        self.h = _sha(self.h + b"f")
        raw = _sha(self.h + b"1") + _sha(self.h + b"2") + _sha(self.h + b"3")
        return int.from_bytes(raw, "big") % P

    def index(self, n):
        self.h = _sha(self.h + b"i")
        return int.from_bytes(self.h, "big") % n


def merkle_build(datas):
    layer = [_sha(b"\x00" + d) for d in datas]
    layers = [layer]
    while len(layer) > 1:
        layer = [_sha(b"\x01" + layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        layers.append(layer)
    return layers


def merkle_path(layers, i):
    return [layers[l][(i >> l) ^ 1] for l in range(len(layers) - 1)]


def merkle_check(root, data, i, path, n):
    depth = n.bit_length() - 1
    if type(path) is not list or len(path) != depth or not all(type(s) is bytes and len(s) == 32 for s in path):
        return False
    h = _sha(b"\x00" + data)
    for l, sib in enumerate(path):
        h = _sha(b"\x01" + sib + h) if (i >> l) & 1 else _sha(b"\x01" + h + sib)
    return h == root


# ============================================================================ AIR
class AIR:
    """Subclass and set: width, n_real, degree, n_constraints, boundary; implement transition().

    transition(cur, nxt, pub) -> list of n_constraints values; each must be a polynomial of total degree <= `degree`
    in the entries of cur, nxt and pub (the public columns). It must evaluate to 0 on every pair of consecutive real
    rows. The core multiplies each by an "active" column (1 on the first n_real-1 rows, else 0) so the random padding
    rows are unconstrained; that adds one to the degree.
    boundary: list of (column, row, value): trace[row][column] == value, row < n_real.
    pub_columns(N): public columns (selectors, round constants), each a list of N field elements.
    extra(): bytes binding any further public input into the transcript."""
    width = 0
    n_real = 0
    degree = 1
    n_constraints = 0
    boundary = []

    def pub_columns(self, N):
        return []

    def transition(self, cur, nxt, pub):
        raise NotImplementedError

    def extra(self):
        return b""


def trace_len(air):
    n = 1
    while n < air.n_real + PAD:
        n *= 2
    return n


def _statement(air, N):
    h = hashlib.sha256()
    h.update(f"stark|{air.width}|{air.n_real}|{air.degree}|{air.n_constraints}|{sorted(air.boundary)}|{N}|"
             f"{BLOWUP}|{QUERIES}|{FINAL_DEG}".encode())
    for col in air.pub_columns(N):
        h.update(b"".join(_enc(v) for v in col))
    h.update(air.extra())
    return h.digest()


def _check_air(air):
    N = trace_len(air)
    k = air.degree  # (degree + 1) - 1 quotient pieces
    assert air.width >= 1 and air.n_real >= 2 and air.n_constraints >= 1 and k >= 1
    assert BLOWUP >= air.degree + 1, "blowup too small for this constraint degree"
    for c, r, v in air.boundary:
        assert 0 <= c < air.width and 0 <= r < air.n_real and 0 <= v < P
    return N, k


def _active(air, N):
    return [1 if r < air.n_real - 1 else 0 for r in range(N)]


# ============================================================================ prover
def prove(air, rows, _force=False, _corrupt=0.0, _fri_cheat=False, _full_final=False):
    """rows: n_real lists of `width` field elements. Test hooks (they play a cheating prover):
    `_force` carries on when the witness is invalid (it truncates polynomials);
    `_corrupt` commits to a trace extension that is perturbed at that fraction of points while the constraint quotient
    and the out-of-domain values stay honest, so only the FRI checks can catch it;
    `_fri_cheat` replaces the first folded FRI layer by an unrelated low-degree polynomial;
    `_full_final` sends the whole final layer as the "final polynomial", whatever its degree."""
    N, k = _check_air(air)
    w = air.width
    if len(rows) != air.n_real or any(len(r) != w or not all(_is_el(x) for x in r) for r in rows):
        raise ProverError("bad trace shape")
    n0 = N * BLOWUP
    g = _root(N)
    om = _root(n0)
    cols = [[rows[r][c] for r in range(air.n_real)] + [secrets.randbelow(P) for _ in range(N - air.n_real)]
            for c in range(w)]
    coeffs_t = [ntt(col, inverse=True) for col in cols]
    lde_t = [coset_eval(cf, n0) for cf in coeffs_t]
    lde_com = [list(col) for col in lde_t]          # what is committed and opened (the honest one unless corrupted)
    if _corrupt:
        for c in range(w):
            for j in range(n0):
                if secrets.randbelow(10000) < int(_corrupt * 10000):
                    lde_com[c][j] = (lde_com[c][j] + 1 + secrets.randbelow(P - 1)) % P
    t_rows = [b"".join(_enc(lde_com[c][j]) for c in range(w)) for j in range(n0)]
    tree_t = merkle_build(t_rows)
    root_t = tree_t[-1][0]

    tr = Transcript(b"air")
    tr.absorb(_statement(air, N))
    tr.absorb(root_t)
    n_b = len(air.boundary)
    alphas = [tr.field() for _ in range(air.n_constraints + n_b)]

    pubs = air.pub_columns(N)
    lde_pub = [coset_eval(ntt(col, inverse=True), n0) for col in pubs]
    lde_act = coset_eval(ntt(_active(air, N), inverse=True), n0)
    # x_j = COSET * om^j ; x^N takes B distinct values
    xs = []
    x = COSET
    for _ in range(n0):
        xs.append(x)
        x = x * om % P
    zinv = batch_inv([(pow(xs[j], N, P) - 1) % P for j in range(BLOWUP)])
    bpts = [pow(g, r, P) for (_, r, _) in air.boundary]
    binv = [batch_inv([(xs[j] - bp) % P for j in range(n0)]) for bp in bpts]
    cp = [0] * n0
    for j in range(n0):
        cur = [lde_t[c][j] for c in range(w)]
        nxt = [lde_t[c][(j + BLOWUP) % n0] for c in range(w)]
        pv = [lde_pub[c][j] for c in range(len(pubs))]
        tv = air.transition(cur, nxt, pv)
        acc = 0
        for i in range(air.n_constraints):
            acc += alphas[i] * tv[i]
        val = acc % P * lde_act[j] % P * zinv[j % BLOWUP] % P
        for bi, (c, r, v) in enumerate(air.boundary):
            val += alphas[air.n_constraints + bi] * (cur[c] - v) % P * binv[bi][j]
        cp[j] = val % P
    cp_coeffs = coset_interp(cp)
    if any(cp_coeffs[k * N:]):
        if not _force:
            raise ProverError("the trace does not satisfy the constraints (quotient is not a polynomial)")
    pieces = [cp_coeffs[i * N:(i + 1) * N] for i in range(k)]
    lde_cp = [coset_eval(pc, n0) for pc in pieces]
    c_rows = [b"".join(_enc(lde_cp[i][j]) for i in range(k)) for j in range(n0)]
    tree_c = merkle_build(c_rows)
    root_c = tree_c[-1][0]
    tr.absorb(root_c)

    z = tr.field()
    while pow(z, N, P) == 1 or pow(z * pow(COSET, -1, P) % P, n0, P) == 1:
        z = tr.field()
    gz = g * z % P
    tz = [horner(coeffs_t[c], z) for c in range(w)]
    tgz = [horner(coeffs_t[c], gz) for c in range(w)]
    cz = [horner(pieces[i], z) for i in range(k)]
    tr.absorb_els(tz + tgz + cz)
    gam = [tr.field() for _ in range(w)]
    gam2 = [tr.field() for _ in range(w)]
    dels = [tr.field() for _ in range(k)]

    iz = batch_inv([(x - z) % P for x in xs])
    igz = batch_inv([(x - gz) % P for x in xs])
    F = [0] * n0
    for j in range(n0):
        s1 = 0
        s2 = 0
        for c in range(w):
            tv = lde_com[c][j]
            s1 += gam[c] * (tv - tz[c])
            s2 += gam2[c] * (tv - tgz[c])
        for i in range(k):
            s1 += dels[i] * (lde_cp[i][j] - cz[i])
        F[j] = (s1 % P * iz[j] + s2 % P * igz[j]) % P

    # ---- FRI
    folds = 0
    while N >> folds > FINAL_DEG:
        folds += 1
    layers = [F]
    trees = [None]
    roots = []
    cur, n, shift = F, n0, COSET
    betas = []
    for l in range(folds):
        beta = tr.field()
        betas.append(beta)
        half = n // 2
        xl = []
        x = shift
        wl = pow(om, 1 << l, P)
        for _ in range(half):
            xl.append(x)
            x = x * wl % P
        ixl = batch_inv([2 * x % P for x in xl])
        nxt = [((cur[i] + cur[i + half]) * pow(2, -1, P) + beta * (cur[i] - cur[i + half]) % P * ixl[i]) % P
               for i in range(half)]
        shift = shift * shift % P
        n = half
        if _fri_cheat and l == 0:
            nxt = coset_eval([secrets.randbelow(P) for _ in range(N // 2)], n, shift)
        cur = nxt
        layers.append(cur)
        if l < folds - 1:
            data = [_enc(cur[i]) + _enc(cur[i + n // 2]) for i in range(n // 2)]
            tree = merkle_build(data)
            trees.append(tree)
            roots.append(tree[-1][0])
            tr.absorb(tree[-1][0])
        else:
            trees.append(None)
    fin = coset_interp(cur, shift)
    keep = N >> folds
    if any(fin[keep:]) and not (_force or _full_final):
        raise ProverError("FRI final layer is not low degree")
    final = fin if _full_final else fin[:keep]
    tr.absorb_els(final)

    queries = []
    for _ in range(QUERIES):
        j0 = tr.index(n0 // 2)
        q = {"pos": []}
        for j in (j0, j0 + n0 // 2):
            q["pos"].append({
                "t": [lde_com[c][j] for c in range(w)], "t_path": merkle_path(tree_t, j),
                "c": [lde_cp[i][j] for i in range(k)], "c_path": merkle_path(tree_c, j)})
        q["layers"] = []
        nl = n0 // 2
        for l in range(1, folds):
            jl = (j0 % nl) % (nl // 2)
            L = layers[l]
            q["layers"].append({"a": L[jl], "b": L[jl + nl // 2], "path": merkle_path(trees[l], jl)})
            nl //= 2
        queries.append(q)
    return {"root_t": root_t, "root_c": root_c, "tz": tz, "tgz": tgz, "cz": cz,
            "fri_roots": roots, "final": final, "queries": queries}


# ============================================================================ verifier
def verify(air, proof):
    """Total function: any malformed or invalid proof gives False."""
    try:
        return _verify(air, proof)
    except Exception:
        return False


def _verify(air, proof):
    N, k = _check_air(air)
    w = air.width
    n0 = N * BLOWUP
    if type(proof) is not dict or set(proof) != {"root_t", "root_c", "tz", "tgz", "cz", "fri_roots", "final", "queries"}:
        return False
    folds = 0
    while N >> folds > FINAL_DEG:
        folds += 1
    keep = N >> folds
    for key, ln in (("tz", w), ("tgz", w), ("cz", k), ("final", keep)):
        v = proof[key]
        if type(v) is not list or len(v) != ln or not all(_is_el(x) for x in v):
            return False
    for key in ("root_t", "root_c"):
        if type(proof[key]) is not bytes or len(proof[key]) != 32:
            return False
    roots = proof["fri_roots"]
    if type(roots) is not list or len(roots) != max(folds - 1, 0) or not all(type(r) is bytes and len(r) == 32 for r in roots):
        return False
    if type(proof["queries"]) is not list or len(proof["queries"]) != QUERIES:
        return False
    g = _root(N)
    om = _root(n0)
    tz, tgz, cz, final = proof["tz"], proof["tgz"], proof["cz"], proof["final"]

    tr = Transcript(b"air")
    tr.absorb(_statement(air, N))
    tr.absorb(proof["root_t"])
    n_b = len(air.boundary)
    alphas = [tr.field() for _ in range(air.n_constraints + n_b)]
    tr.absorb(proof["root_c"])
    z = tr.field()
    while pow(z, N, P) == 1 or pow(z * pow(COSET, -1, P) % P, n0, P) == 1:
        z = tr.field()
    gz = g * z % P
    tr.absorb_els(tz + tgz + cz)
    gam = [tr.field() for _ in range(w)]
    gam2 = [tr.field() for _ in range(w)]
    dels = [tr.field() for _ in range(k)]

    # ---- out-of-domain consistency of the constraint quotient
    pubs = air.pub_columns(N)
    pub_coeffs = [ntt(col, inverse=True) for col in pubs]
    act_coeffs = ntt(_active(air, N), inverse=True)
    pz = [horner(cf, z) for cf in pub_coeffs]
    tv = air.transition(tz, tgz, pz)
    acc = 0
    for i in range(air.n_constraints):
        acc += alphas[i] * tv[i]
    zn1 = (pow(z, N, P) - 1) % P
    lhs = acc % P * horner(act_coeffs, z) % P * pow(zn1, -1, P) % P
    for bi, (c, r, v) in enumerate(air.boundary):
        lhs += alphas[air.n_constraints + bi] * (tz[c] - v) % P * pow((z - pow(g, r, P)) % P, -1, P)
    lhs %= P
    rhs = 0
    zN = pow(z, N, P)
    for i in range(k):
        rhs += pow(zN, i, P) * cz[i]
    if lhs != rhs % P:
        return False

    # ---- FRI challenges
    betas = []
    for l in range(folds):
        betas.append(tr.field())
        if l < folds - 1:
            tr.absorb(roots[l])
    tr.absorb_els(final)

    half2 = pow(2, -1, P)
    for q in proof["queries"]:
        j0 = tr.index(n0 // 2)
        if type(q) is not dict or set(q) != {"pos", "layers"} or type(q["pos"]) is not list or len(q["pos"]) != 2:
            return False
        if type(q["layers"]) is not list or len(q["layers"]) != max(folds - 1, 0):
            return False
        vals = []
        for pi, j in enumerate((j0, j0 + n0 // 2)):
            p = q["pos"][pi]
            if type(p) is not dict or set(p) != {"t", "t_path", "c", "c_path"}:
                return False
            if type(p["t"]) is not list or len(p["t"]) != w or not all(_is_el(x) for x in p["t"]):
                return False
            if type(p["c"]) is not list or len(p["c"]) != k or not all(_is_el(x) for x in p["c"]):
                return False
            if not merkle_check(proof["root_t"], b"".join(_enc(x) for x in p["t"]), j, p["t_path"], n0):
                return False
            if not merkle_check(proof["root_c"], b"".join(_enc(x) for x in p["c"]), j, p["c_path"], n0):
                return False
            x = COSET * pow(om, j, P) % P
            iz = pow((x - z) % P, -1, P)
            igz = pow((x - gz) % P, -1, P)
            s1 = 0
            s2 = 0
            for c in range(w):
                s1 += gam[c] * (p["t"][c] - tz[c])
                s2 += gam2[c] * (p["t"][c] - tgz[c])
            for i in range(k):
                s1 += dels[i] * (p["c"][i] - cz[i])
            vals.append((s1 % P * iz + s2 % P * igz) % P)
        # fold layer 0 -> 1
        x0 = COSET * pow(om, j0, P) % P
        a, b = vals
        v = ((a + b) * half2 + betas[0] * (a - b) % P * pow(2 * x0 % P, -1, P)) % P if folds >= 1 else a
        nl = n0 // 2
        for l in range(1, folds):
            lay = q["layers"][l - 1]
            if type(lay) is not dict or set(lay) != {"a", "b", "path"} or not (_is_el(lay["a"]) and _is_el(lay["b"])):
                return False
            idx = j0 % nl
            jl = idx % (nl // 2)
            if not merkle_check(roots[l - 1], _enc(lay["a"]) + _enc(lay["b"]), jl, lay["path"], nl // 2):
                return False
            if (lay["b"] if idx >= nl // 2 else lay["a"]) != v:
                return False
            xl = pow(COSET, 1 << l, P) * pow(om, (1 << l) * jl, P) % P
            v = ((lay["a"] + lay["b"]) * half2 + betas[l] * (lay["a"] - lay["b"]) % P * pow(2 * xl % P, -1, P)) % P
            nl //= 2
        idx = j0 % nl
        xf = pow(COSET, 1 << folds, P) * pow(om, (1 << folds) * idx, P) % P
        if horner(final, xf) != v:
            return False
    return True


def proof_size_bytes(proof):
    def sz(o):
        if type(o) is int:
            return EL
        if type(o) is bytes:
            return len(o)
        if type(o) is list:
            return sum(sz(x) for x in o)
        if type(o) is dict:
            return sum(sz(x) for x in o.values())
        return 0
    return sz(proof)


# ============================================================================ self-test
class FibAIR(AIR):
    """(a, b) -> (b, a + b). Public: the first row (1, 1) and the value of `b` in the last row."""
    width = 2
    degree = 1
    n_constraints = 2

    def __init__(self, steps, out):
        self.n_real = steps + 1
        self.boundary = [(0, 0, 1), (1, 0, 1), (1, steps, out)]

    def transition(self, cur, nxt, pub):
        return [(nxt[0] - cur[1]) % P, (nxt[1] - cur[0] - cur[1]) % P]


def fib_rows(steps):
    a, b, rows = 1, 1, []
    for _ in range(steps + 1):
        rows.append([a, b])
        a, b = b, (a + b) % P
    return rows


class SqAIR(AIR):
    """x -> x^2 + c_r with a PUBLIC round column c. The start value is SECRET (not constrained); the end is public."""
    width = 1
    degree = 2
    n_constraints = 1

    def __init__(self, consts, out):
        self.consts = consts
        self.n_real = len(consts) + 1
        self.boundary = [(0, len(consts), out)]

    def pub_columns(self, N):
        return [list(self.consts) + [0] * (N - len(self.consts))]

    def transition(self, cur, nxt, pub):
        return [(nxt[0] - cur[0] * cur[0] - pub[0]) % P]


def sq_rows(x0, consts):
    rows, x = [[x0]], x0
    for c in consts:
        x = (x * x + c) % P
        rows.append([x])
    return rows, x


def _selftest():
    import copy
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def refuses(fn):
        try:
            fn()
            return False
        except ProverError:
            return True

    print(f"field: {P.bit_length()}-bit, blowup {BLOWUP}, {QUERIES} queries, min padding {PAD} rows")
    print("\n0) field and FFT sanity")
    check("GEN has order exactly 2^K2", pow(GEN, 1 << (K2 - 1), P) != 1 and pow(GEN, 1 << K2, P) == 1)
    a = [secrets.randbelow(P) for _ in range(64)]
    check("NTT round trip", ntt(ntt(a), inverse=True) == a)
    x = secrets.randbelow(P)
    ev = coset_eval(a, 64)
    check("coset evaluation agrees with Horner", ev[5] == horner(a, COSET * pow(_root(64), 5, P) % P))

    print("\n1) honest proofs")
    steps = 32
    rows = fib_rows(steps)
    out = rows[-1][1]
    air = FibAIR(steps, out)
    pf = prove(air, rows)
    check("Fibonacci AIR (degree 1): accepted", verify(air, pf))
    print(f"    proof size {proof_size_bytes(pf) / 1024:.0f} KiB, trace length N = {trace_len(air)}")
    consts = [secrets.randbelow(P) for _ in range(20)]
    sx0 = secrets.randbelow(P)
    srows, sout = sq_rows(sx0, consts)
    sair = SqAIR(consts, sout)
    spf = prove(sair, srows)
    check("squaring chain with a public column (degree 2): accepted", verify(sair, spf))

    print("\n2) wrong statements")
    check("proof for output y presented against output y+1: rejected", verify(FibAIR(steps, (out + 1) % P), pf), False)
    check("proof for another number of steps: rejected", verify(FibAIR(steps + 1, out), pf), False)
    check("proof checked against different public constants: rejected",
          verify(SqAIR([(c + 1) % P for c in consts], sout), spf), False)
    check("honest prover refuses a false output", refuses(lambda: prove(FibAIR(steps, (out + 1) % P), rows)))
    bad = copy.deepcopy(rows)
    bad[10][1] = (bad[10][1] + 1) % P
    check("honest prover refuses a trace with one broken transition", refuses(lambda: prove(air, bad)))

    print("\n3) cheating provers who ignore the refusal (polynomials truncated)")
    check("broken transition, forced proof: rejected", verify(air, prove(air, bad, _force=True)), False)
    check("false output, forced proof: rejected",
          verify(FibAIR(steps, (out + 1) % P), prove(FibAIR(steps, (out + 1) % P), rows, _force=True)), False)
    bad2 = copy.deepcopy(srows)
    bad2[0][0] = (bad2[0][0] + 7) % P               # start value changed but the rest kept: transition 0 breaks
    check("squaring chain with an inconsistent first step, forced: rejected",
          verify(sair, prove(sair, bad2, _force=True)), False)
    check("committed trace extension corrupted at 30% of points (honest quotient and out-of-domain data): rejected",
          verify(air, prove(air, rows, _corrupt=0.30, _force=True)), False)
    check("committed trace extension corrupted at 3% of points: rejected",
          verify(air, prove(air, rows, _corrupt=0.03, _force=True)), False)
    check("a fake first FRI layer (low degree, unrelated to the trace, validly committed): rejected",
          verify(air, prove(air, rows, _fri_cheat=True, _force=True)), False)
    check("a corrupted trace with the whole last FRI layer sent as the final polynomial: rejected",
          verify(air, prove(air, rows, _corrupt=0.30, _full_final=True)), False)

    print("\n4) every field of a proof is tied down")
    def mut(label, fn, a=air, p=pf):
        q = copy.deepcopy(p)
        fn(q)
        check(f"{label}: rejected", verify(a, q), False)

    def flip(b):
        return bytes([b[0] ^ 1]) + b[1:]

    mut("root_t bit flipped", lambda q: q.__setitem__("root_t", flip(q["root_t"])))
    mut("root_c bit flipped", lambda q: q.__setitem__("root_c", flip(q["root_c"])))
    mut("out-of-domain trace value +1", lambda q: q["tz"].__setitem__(0, (q["tz"][0] + 1) % P))
    mut("out-of-domain next-row value +1", lambda q: q["tgz"].__setitem__(1, (q["tgz"][1] + 1) % P))
    mut("out-of-domain quotient piece +1", lambda q: q["cz"].__setitem__(0, (q["cz"][0] + 1) % P))
    mut("a FRI root bit flipped", lambda q: q["fri_roots"].__setitem__(0, flip(q["fri_roots"][0])))
    mut("final polynomial coefficient +1", lambda q: q["final"].__setitem__(0, (q["final"][0] + 1) % P))
    mut("a query's trace value +1", lambda q: q["queries"][3]["pos"][0]["t"].__setitem__(0, (q["queries"][3]["pos"][0]["t"][0] + 1) % P))
    mut("a query's quotient value +1", lambda q: q["queries"][5]["pos"][1]["c"].__setitem__(0, (q["queries"][5]["pos"][1]["c"][0] + 1) % P))
    mut("a Merkle path element flipped", lambda q: q["queries"][7]["pos"][0]["t_path"].__setitem__(0, flip(q["queries"][7]["pos"][0]["t_path"][0])))
    mut("a quotient Merkle path element flipped", lambda q: q["queries"][8]["pos"][1]["c_path"].__setitem__(2, flip(q["queries"][8]["pos"][1]["c_path"][2])))
    mut("a FRI layer value +1", lambda q: q["queries"][2]["layers"][0].__setitem__("a", (q["queries"][2]["layers"][0]["a"] + 1) % P))
    mut("a FRI layer path element flipped", lambda q: q["queries"][2]["layers"][0]["path"].__setitem__(0, flip(q["queries"][2]["layers"][0]["path"][0])))
    mut("a Merkle path extended by one element", lambda q: q["queries"][4]["pos"][0]["t_path"].append(q["queries"][4]["pos"][0]["t_path"][0]))
    mut("a Merkle path truncated", lambda q: q["queries"][4]["pos"][1]["c_path"].pop())
    mut("a Merkle path element replaced by a non-bytes value", lambda q: q["queries"][4]["pos"][0]["t_path"].__setitem__(1, 5))
    mut("a query's layer list emptied", lambda q: q["queries"][6].__setitem__("layers", []))
    mut("a query dropped", lambda q: q["queries"].pop())
    mut("queries reordered", lambda q: q["queries"].reverse())
    mut("two queries swapped", lambda q: q["queries"].__setitem__(0, q["queries"][1]))
    mut("trace value as non-canonical integer (x + P)", lambda q: q["queries"][0]["pos"][0]["t"].__setitem__(0, q["queries"][0]["pos"][0]["t"][0] + P))
    mut("out-of-domain value as non-canonical integer", lambda q: q["tz"].__setitem__(0, q["tz"][0] + P))
    mut("unknown extra key", lambda q: q.__setitem__("extra", 1))
    mut("final polynomial too long", lambda q: q["final"].append(0))
    check("None rejected", verify(air, None), False)
    check("empty dict rejected", verify(air, {}), False)

    print("\n5) a proof is not transferable between two different proofs of the same statement")
    pf2 = prove(air, rows)
    check("second honest proof of the same statement also accepted", verify(air, pf2))
    check("the two proofs differ (random padding rows)", pf["root_t"] != pf2["root_t"])
    q = copy.deepcopy(pf)
    q["queries"] = copy.deepcopy(pf2["queries"])
    check("queries of proof 2 under the roots of proof 1: rejected", verify(air, q), False)

    print("\n6) witness hiding (statistical sanity only)")
    blob = repr(spf).encode()
    check("the secret start value of the squaring chain does not appear in the proof",
          str(sx0).encode() not in blob and sx0.to_bytes(EL, "big") not in blob)
    ps = [prove(sair, srows) for _ in range(3)]
    opened = [{v for qq in p["queries"] for pos in qq["pos"] for v in pos["t"]} for p in ps]
    check("three proofs of the same witness open pairwise different values", not (opened[0] & opened[1]) and not (opened[0] & opened[2]))

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy STARK, soundness is conjectured (not proven) and zero knowledge is argued (not proven); unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
