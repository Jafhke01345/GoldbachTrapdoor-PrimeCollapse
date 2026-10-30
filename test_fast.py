"""
test_fast.py - differential tests: C (zkrp_fast) vs the Python reference (zkrp_toy).

  * Python proofs  -> C verifier   (honest and tampered), verdicts must match Python's
  * C proofs       -> Python verifier (must all verify)
  * tampered C proofs -> both verifiers must reject
  * C prover refuses out-of-range / bad inputs

Usage: python test_fast.py [path/to/zkrp_toy_dir] [path/to/zkrp_fast]
Exit code 0 only if everything agrees.
"""
import copy
import os
import secrets
import subprocess
import sys
import tempfile

PY_DIR = sys.argv[1] if len(sys.argv) > 1 else "../../package"
EXE = sys.argv[2] if len(sys.argv) > 2 else "./zkrp_fast"
sys.path.insert(0, PY_DIR)
import zkrp_toy as Z  # noqa: E402

tmp = tempfile.mkdtemp()
PARAMS = os.path.join(tmp, "params.txt")
with open(PARAMS, "w") as f:
    f.write(f"{Z.P:x} {Z.Q:x} {Z.G:x} {Z.H:x}\n")

NB = Z.N_BITS
failures = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        failures.append(name)


def to_line(pub):
    toks = [pub["c"], pub["Ca"], pub["Cb"], pub["T"], pub["z"]]
    for key in ("rp_a", "rp_x"):
        Bs, proofs = pub[key]
        toks += list(Bs)
        for pr in proofs:
            toks += list(pr)
    return " ".join(f"{t:x}" for t in toks)


def from_tokens(toks):
    v = [int(t, 16) for t in toks]
    pub = {"c": v[0], "Ca": v[1], "Cb": v[2], "T": v[3], "z": v[4]}
    pos = 5
    for key in ("rp_a", "rp_x"):
        Bs = v[pos:pos + NB]; pos += NB
        proofs = []
        for _ in range(NB):
            proofs.append(tuple(v[pos:pos + 6])); pos += 6
        pub[key] = (Bs, proofs)
    return pub


def c_verify(pubs):
    path = os.path.join(tmp, "tr.txt")
    with open(path, "w") as f:
        f.write("\n".join(to_line(p) for p in pubs) + "\n")
    out = subprocess.run([EXE, "verify", PARAMS, path], capture_output=True, text=True, timeout=300)
    return out.stdout.split()


def c_prove(pairs):
    path = os.path.join(tmp, "pairs.txt")
    with open(path, "w") as f:
        f.write("\n".join(f"{a} {b}" for a, b in pairs) + "\n")
    out = subprocess.run([EXE, "prove", PARAMS, path], capture_output=True, text=True, timeout=300)
    return out.stdout.strip().splitlines()


def tamper(pub, how):
    p = copy.deepcopy(pub)
    if how == "Ca":       p["Ca"] = p["Ca"] * Z.G % Z.P
    elif how == "z":      p["z"] = (p["z"] + 1) % Z.Q
    elif how == "c":      p["c"] += 1
    elif how == "T":      p["T"] = p["T"] * Z.H % Z.P
    elif how == "bitB":   p["rp_a"][0][3] = p["rp_a"][0][3] * Z.G % Z.P
    elif how == "bitZ":
        pr = list(p["rp_x"][1][5]); pr[4] = (pr[4] + 1) % Z.Q; p["rp_x"][1][5] = tuple(pr)
    elif how == "bitE":
        pr = list(p["rp_a"][1][7]); pr[2] = (pr[2] + 1) % Z.Q; p["rp_a"][1][7] = tuple(pr)
    elif how == "bitT":
        pr = list(p["rp_a"][1][2]); pr[0] = pr[0] * Z.H % Z.P; p["rp_a"][1][2] = tuple(pr)
    elif how == "swap":
        p["rp_a"], p["rp_x"] = p["rp_x"], p["rp_a"]
    return p


print(f"group: {Z.P.bit_length()}-bit P, {Z.Q.bit_length()}-bit Q, range 2^{NB}")

print("\n1) Python proofs -> C verifier")
honest = [Z.prove(a, a + 2 * secrets.randbelow(2 ** (NB - 3))) for a in (secrets.randbelow(2 ** (NB - 2)) for _ in range(12))]
honest += [Z.prove(1009, 2003), Z.prove(0, 0), Z.prove(0, 2), Z.prove(5, 5), Z.prove(2 ** 30, 2 ** 30 + 2 ** 29 - 2)]
py = [Z.verify(p) for p in honest]
cv = c_verify(honest)
check(f"{len(honest)} honest Python proofs all accepted by Python", all(py))
check(f"{len(honest)} honest Python proofs all accepted by C", cv == ["1"] * len(honest))

cases = []
for how in ("Ca", "z", "c", "T", "bitB", "bitZ", "bitE", "bitT", "swap"):
    for p in honest[:3]:
        cases.append((how, tamper(p, how)))
py_t = [Z.verify(p) for _, p in cases]
c_t = c_verify([p for _, p in cases])
check(f"{len(cases)} tampered proofs: Python rejects all", not any(py_t))
check(f"{len(cases)} tampered proofs: C rejects all", c_t == ["0"] * len(cases))
check("verdicts agree on every single case", [("1" if x else "0") for x in py_t] == c_t)

# cheating proofs that Python's prover can still build with _cheat (negative a, a > b, wraparound)
cheats = [Z.prove(-3, 1001, _cheat=True), Z.prove(2003, 1009, _cheat=True), Z.prove(2 ** NB + 5, 2 ** NB + 9, _cheat=True)]
check("cheating proofs (negative a, a>b, a>=2^N): Python rejects", not any(Z.verify(p) for p in cheats))
check("cheating proofs: C rejects", c_verify(cheats) == ["0"] * len(cheats))

print("\n2) C proofs -> Python verifier")
pairs = [(1009, 2003), (0, 0), (0, 2), (7, 7), (2 ** 30, 2 ** 30 + 2 ** 29 - 2)]
pairs += [(a, a + 2 * secrets.randbelow(2 ** (NB - 3))) for a in (secrets.randbelow(2 ** (NB - 2)) for _ in range(20))]
lines = c_prove(pairs)
check("C prover returned one transcript per pair", len(lines) == len(pairs) and "ERR" not in lines)
parsed = [from_tokens(l.split()) for l in lines]
check("every C proof has the right values (c = (a+b)/2)", all(p["c"] == (a + b) // 2 for p, (a, b) in zip(parsed, pairs)))
check(f"all {len(parsed)} C proofs accepted by Python", all(Z.verify(p) for p in parsed))
check("all C proofs accepted by C", c_verify(parsed) == ["1"] * len(parsed))
check("C proofs differ from each other (fresh randomness)", len({l.split()[1] for l in lines}) == len(lines))

print("\n3) tampered C proofs")
tc = [tamper(p, h) for h in ("Ca", "z", "c", "T", "bitB", "bitZ", "bitE", "bitT", "swap") for p in parsed[:3]]
check("tampered C proofs rejected by Python", not any(Z.verify(p) for p in tc))
check("tampered C proofs rejected by C", c_verify(tc) == ["0"] * len(tc))

print("\n4) C prover refuses bad inputs")
bad = [(3, 1), (1, 2), (2 ** 33, 2 ** 33), (5, 4), (2 ** 40, 2 ** 40 + 2)]     # a>b, odd sum, a>=2^N, odd, a>=2^N
res = c_prove(bad)
check("a > b, odd sum and out-of-range inputs all give ERR", res == ["ERR"] * len(bad))

print("\n5) malformed input files")
open(os.path.join(tmp, "junk.txt"), "w").write("zz 12 34\n")
out = subprocess.run([EXE, "verify", PARAMS, os.path.join(tmp, "junk.txt")], capture_output=True, text=True, timeout=60)
check("junk transcript does not crash (ERR / no verdict, exit 0)", out.returncode == 0 and "1" not in out.stdout.split())
open(os.path.join(tmp, "short.txt"), "w").write(to_line(honest[0]).rsplit(" ", 5)[0] + "\n")
out = subprocess.run([EXE, "verify", PARAMS, os.path.join(tmp, "short.txt")], capture_output=True, text=True, timeout=60)
check("truncated transcript is not accepted", out.returncode == 0 and "1" not in out.stdout.split())
oversize = to_line(honest[0]).split()
oversize[1] = "f" * 70
open(os.path.join(tmp, "big.txt"), "w").write(" ".join(oversize) + "\n")
out = subprocess.run([EXE, "verify", PARAMS, os.path.join(tmp, "big.txt")], capture_output=True, text=True, timeout=60)
check("oversized (>256-bit) token is not accepted", out.returncode == 0 and "1" not in out.stdout.split())
oob = to_line(honest[0]).split(); oob[1] = f"{Z.P + 5:x}"          # Ca >= P
open(os.path.join(tmp, "oob.txt"), "w").write(" ".join(oob) + "\n")
out = subprocess.run([EXE, "verify", PARAMS, os.path.join(tmp, "oob.txt")], capture_output=True, text=True, timeout=60)
check("group element >= P is rejected", out.stdout.split() == ["0"])

print("\n6) forged range proofs (a malicious prover's best attempts)")
P_, Q_, G_, H_, GI_ = Z.P, Z.Q, Z.G, Z.H, Z.G_INV
rand_q = lambda: secrets.randbelow(Q_)
rand_el = lambda: pow(H_, secrets.randbelow(Q_ - 1) + 1, P_)


def forged_full(B, ctx, bit=None):
    """Satisfies BOTH branch equations for any B by simulating both; only the hash-sum check can stop it."""
    e0, e1, z0, z1 = rand_q(), rand_q(), rand_q(), rand_q()
    T0 = pow(H_, z0, P_) * pow(B, (-e0) % Q_, P_) % P_
    T1 = pow(H_, z1, P_) * pow(B * GI_ % P_, (-e1) % Q_, P_) % P_
    return (T0, T1, e0, e1, z0, z1)


def half_forged(valid):
    def make(B, ctx, bit=None):
        Y = [B, B * GI_ % P_]
        e_s, z_s = rand_q(), rand_q()
        T = [None, None]
        T[valid] = pow(H_, z_s, P_) * pow(Y[valid], (-e_s) % Q_, P_) % P_
        T[1 - valid] = rand_el()
        e = Z.challenge(ctx, B, T[0], T[1])
        e_o, z_o = (e - e_s) % Q_, rand_q()
        es, zs = [None, None], [None, None]
        es[valid], es[1 - valid] = e_s, e_o
        zs[valid], zs[1 - valid] = z_s, z_o
        return (T[0], T[1], es[0], es[1], zs[0], zs[1])
    return make


def garbage(B, ctx, bit=None):
    return (rand_el(), rand_el(), rand_q(), rand_q(), rand_q(), rand_q())


def honest_maker(B, ctx, bit):
    return None            # replaced below by Z.or_prove with the real randomness


def custom_proof(a, b, ms, makers, nc_Ca=False, nc_T=False, nc_bit=None):
    """Build a transcript for a + b = 2c with arbitrary 'bit values' ms (sum ms[i]*2^i == a)
    and per-bit proof makers. nc_* produce non-canonical (+P) encodings with consistent hashes."""
    assert sum(m << i for i, m in enumerate(ms)) == a and (a + b) % 2 == 0
    c = (a + b) // 2
    x = c - a
    for _ in range(1000):
        ra, rb = rand_q(), rand_q()
        Ca, Cb = Z.commit(a, ra), Z.commit(b, rb)
        if not nc_Ca or Ca + P_ < 2 ** 256:
            break
    rs = [rand_q() for _ in range(NB)]
    rs[0] = (ra - sum(rs[i] << i for i in range(1, NB))) % Q_
    Bs, proofs = [], []
    for i in range(NB):
        B = Z.commit(ms[i], rs[i])
        if nc_bit == i:
            B += P_
        Bs.append(B)
        proofs.append(Z.or_prove(B, ms[i], rs[i], f"a:{i}") if makers[i] is None else makers[i](B, f"a:{i}"))
    rp_x = Z.range_prove(x, (-ra) % Q_, NB, "x")
    s = (ra + rb) % Q_
    for _ in range(1000):
        t = rand_q()
        T = pow(H_, t, P_)
        if not nc_T or T + P_ < 2 ** 256:
            break
    Ca_e, T_e = (Ca + P_ if nc_Ca else Ca), (T + P_ if nc_T else T)
    e = Z.challenge(c, Ca_e, Cb, T_e)
    return {"c": c, "Ca": Ca_e, "Cb": Cb, "T": T_e, "z": (t + e * s) % Q_, "rp_a": (Bs, proofs), "rp_x": rp_x}


zeros = [0] * NB
ms_neg = [-3] + [0] * (NB - 1)                         # "a = -3": bit 0 holds the non-bit value -3
ms_top = [0] * (NB - 1) + [2]                          # "a = 2^32": top bit holds the non-bit value 2
none = [None] * NB
sanity = custom_proof(1009, 2003, [(1009 >> i) & 1 for i in range(NB)], none)
check("sanity: custom builder with honest bits produces an accepted proof (Python and C)",
      Z.verify(sanity) and c_verify([sanity]) == ["1"])

forgeries = {
    "non-bit value -3 with both OR branches simulated (hash-sum check must stop it)":
        custom_proof(-3, 1001, ms_neg, [forged_full] + [None] * (NB - 1)),
    "non-bit value -3, branch 0 valid / branch 1 garbage (e0+e1 correct)":
        custom_proof(-3, 1001, ms_neg, [half_forged(0)] + [None] * (NB - 1)),
    "non-bit value -3, branch 1 valid / branch 0 garbage (e0+e1 correct)":
        custom_proof(-3, 1001, ms_neg, [half_forged(1)] + [None] * (NB - 1)),
    "a = 2^32 hidden in the TOP bit (index 31), garbage proof there":
        custom_proof(2 ** 32, 2 ** 32 + 1000, ms_top, [None] * (NB - 1) + [garbage]),
    "a = 2^32 hidden in the TOP bit, branch-0-valid half forgery":
        custom_proof(2 ** 32, 2 ** 32 + 1000, ms_top, [None] * (NB - 1) + [half_forged(0)]),
    "non-bit value 2 hidden in a MIDDLE bit (index 13), garbage proof there":
        custom_proof(2 ** 13 * 2, 2 ** 13 * 2 + 1000, [0] * 13 + [2] + [0] * (NB - 14), [None] * 13 + [garbage] + [None] * (NB - 14)),
}
for name, pub in forgeries.items():
    check(f"Python rejects: {name}", not Z.verify(pub))
    check(f"C rejects:      {name}", c_verify([pub]) == ["0"])

print("\n7) non-canonical encodings (value + P): valid mathematically, rejected by C by design")
canon = {
    "Ca encoded as Ca + P (hashes recomputed consistently)": custom_proof(1009, 2003, [(1009 >> i) & 1 for i in range(NB)], none, nc_Ca=True),
    "T encoded as T + P (hashes recomputed consistently)": custom_proof(1009, 2003, [(1009 >> i) & 1 for i in range(NB)], none, nc_T=True),
}
for i in (0, 9, 31):
    pass
for name, pub in canon.items():
    check(f"C rejects: {name}", c_verify([pub]) == ["0"])
nc_ok = 0
for i in (0, 9):
    for _ in range(200):                                # need B + P to still fit in 256 bits
        try:
            pub = custom_proof(1009, 2003, [(1009 >> j) & 1 for j in range(NB)], none, nc_bit=i)
        except Exception:
            continue
        if all(b < 2 ** 256 for b in pub["rp_a"][0]):
            break
    else:
        raise SystemExit("could not build a +P bit commitment that fits in 256 bits")
    check(f"C rejects: bit commitment {i} encoded as B + P", c_verify([pub]) == ["0"])

print("\n8) integer-level bounds: the C verifier must reject c claimed only modulo Q, and accept the extremes")
def forge_claim(a, b, c_claim):
    c = (a + b) // 2
    ra, rb = secrets.randbelow(Z.Q), secrets.randbelow(Z.Q)
    Ca, Cb = Z.commit(a, ra), Z.commit(b, rb)
    rp_a = Z.range_prove(a, ra, NB, "a")
    rp_x = Z.range_prove(c - a, (-ra) % Z.Q, NB, "x")
    tt = secrets.randbelow(Z.Q)
    T = pow(Z.H, tt, Z.P)
    z = (tt + Z.challenge(c_claim, Ca, Cb, T) * ((ra + rb) % Z.Q)) % Z.Q
    return {"c": c_claim, "Ca": Ca, "Cb": Cb, "T": T, "z": z, "rp_a": rp_a, "rp_x": rp_x}

for label, shift in (("c + Q", Z.Q), ("c + 2Q", 2 * Z.Q)):
    pub = forge_claim(1009, 2003, 1506 + shift)
    if pub["c"] < 2 ** 256:
        check(f"C rejects field-wrapped claim {label}", c_verify([pub]) == ["0"])
pub = forge_claim(1009, 2003, 1506 + 2 ** 33)       # fits in 256 bits, residue differs: range proofs must fail anyway
check("C rejects claim c = true c + 2^33 (out of the integer bound)", c_verify([pub]) == ["0"])
M = 2 ** NB
extremes = [(0, 0), (77, 77), (0, 2 * (M - 1)), (M - 1, 3 * (M - 1))]
got = c_prove(extremes)
check("C prover accepts all four boundary pairs", len(got) == 4)
if len(got) == 4:
    toks = [g.split() for g in got]
    check("Python verifier accepts C proofs at the boundaries", all(Z.verify(from_tokens(t_)) for t_ in toks))
check("C prover refuses a = 2^N", c_prove([(M, M + 2)]) == ["ERR"])
check("C prover refuses c - a = 2^N", c_prove([(0, 2 * M)]) == ["ERR"])

print(f"\n{'ALL DIFFERENTIAL TESTS PASSED' if not failures else str(len(failures)) + ' FAILED: ' + '; '.join(failures)}")
sys.exit(1 if failures else 0)
