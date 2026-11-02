"""
stark_primality.py - a STARK (hash-based, see stark_core.py) that a COMMITTED number n below 2^64 is prime,
via a recursive Pocklington certificate that stays hidden. Nothing is opened: not n, not q, R, the bases or the
Bezout witnesses, and not the salt.

    Public    : cm  = commit(n, salt)   (a MiMC-style algebraic commitment, see below)
                the size profile (bit bounds of n_0 > n_1 > ... , default (64, 33, 17, 9, 5)) and the terminal prime 3
    Witness   : n = n_0, salt, and for each tier i: n_i = 2 q_i R_i + 1, q_i = n_{i+1} (q of the last tier is 3),
                bases a2_i, aq_i and Bezout witnesses w2_i, wq_i
    The AIR enforces, for every tier (all arithmetic is modular multiplication gadgets with 64-bit range checks):
        n = 2 q R + 1 over the integers and q*R computed exactly; 1 <= R <= 2q - 1 (so 4 q^2 > n);
        y2 = a2^((n-1)/2) with y2^2 = 1 (mod n) and (y2 - 1) w2 = 1 (mod n);
        yq = aq^((n-1)/q) with yq^q = 1 (mod n) and (yq - 1) wq = 1 (mod n);
        n_{i+1} = q_i, the chain ends at q = 3, and cm = commit(n_0, salt).
    By Pocklington's theorem each n_i is then prime, hence n_0 is.

Exponents are hidden: every exponentiation is a square-and-multiply ladder whose bits are witness columns,
accumulated into a register that is compared with the hidden number it must equal.

THE COMMITMENT: cm = S_R + salt + n where S_{r+1} = (S_r + salt + k_r)^3 (MiMC, 114 rounds, S_0 = n) in the same
180-bit field. It is a home-made use of a published permutation shape: unreviewed, roughly 90-bit collision
resistance, and it is NOT linked to the Pedersen commitment of the rest of the repository (a different group
and field). Linking the two would need the discrete-log group inside this circuit or a shared commitment.

LEAKS (public by construction): the size profile, i.e. the length of the chain. WHAT THIS IS NOT: audited,
constant-time, a proof of zero knowledge (see stark_core.py: argued, not proven).

Run `python stark_primality.py` for the self-test (it takes a few minutes).
"""
import hashlib
import random
import secrets
import sys
import time

import stark_core as S

P = S.P
PROFILE = (64, 33, 17, 9, 5)
MIMC_ROUNDS = 114
WB = 64                                                  # range-check width
COLS = ["A", "B", "Q", "V", "G", "EB", "EA", "N", "QR", "RR", "MM", "S", "U", "KEY", "MSG", "CM"]
IDX = {c: i for i, c in enumerate(COLS)}
BQ0 = len(COLS)
BV0 = BQ0 + WB
WIDTH = BV0 + WB
KC = [int.from_bytes(hashlib.sha256(b"stark_primality|mimc|%d" % r).digest(), "big") % P for r in range(MIMC_ROUNDS)]
PUBN = ["s_mm", "s_bez", "s_sqf", "s_mul", "s_ferm", "s_rG", "s_rT", "s_rR", "s_start", "t_sq2mul", "t_mul2x",
        "t_mul2bez", "t_tm", "t_ferm2bez", "t_bez2e3", "t_holdG", "t_reg", "t_tier", "s_rel", "s_chk_m", "s_chk_2r",
        "s_chk_q", "s_mimc", "kc", "s_mstart", "s_mend", "t_mimcH", "t_commit"]


# ============================================================================ commitment
def commit(n, salt):
    s = n % P
    for r in range(MIMC_ROUNDS):
        t = (s + salt + KC[r]) % P
        s = t * t % P * t % P
    return (s + salt + n) % P


# ============================================================================ layout
def tier_bits(profile, i):
    """(bits of (n-1)/2, bits of 2R, bits of q) for tier i."""
    Bn = profile[i]
    Bq = profile[i + 1] if i + 1 < len(profile) else 2
    return Bn - 1, Bq + 2, Bq


def layout(profile=PROFILE):
    d = []
    for r in range(MIMC_ROUNDS + 1):
        d.append({"k": "mimc", "r": r, "tier": None})
    first_rows = []

    def block(blk, L, tier):
        for b in range(L):
            d.append({"k": "sq", "start": b == 0, "blk": blk, "tier": tier})
            d.append({"k": "mul", "lastmul": b == L - 1, "blk": blk, "tier": tier})

    for i in range(len(profile)):
        L1, L2, L3 = tier_bits(profile, i)
        first_rows.append(len(d))
        d.append({"k": "rngG", "first": True, "blk": 1, "tier": i})
        block(1, L1, i)
        d.append({"k": "ferm", "chk": "m", "tier": i})
        d.append({"k": "bez", "which": 2, "tier": i})
        d.append({"k": "rngG", "blk": 2, "tier": i})
        block(2, L2, i)
        d.append({"k": "bez", "which": 3, "tier": i})
        block(3, L3, i)
        d.append({"k": "ferm", "chk": "q", "tier": i})
        d.append({"k": "rngT", "tier": i})
        d.append({"k": "rngR", "last": True, "tier": i})
    d.append({"k": "end", "tier": None})
    return d, first_rows


def pub_table(desc, profile, N):
    T = len(profile)
    cols = {n: [0] * N for n in PUBN}
    for r, d in enumerate(desc):
        k = d["k"]
        nx = desc[r + 1]["k"] if r + 1 < len(desc) else None
        if k in ("sq", "mul", "ferm"):
            cols["s_mm"][r] = 1
        if k in ("sq", "ferm"):
            cols["s_sqf"][r] = 1
        if k == "mul":
            cols["s_mul"][r] = 1
        if k == "ferm":
            cols["s_ferm"][r] = 1
        if k == "bez":
            cols["s_bez"][r] = 1
        if k == "rngG":
            cols["s_rG"][r] = 1
        if k == "rngT":
            cols["s_rT"][r] = 1
        if k == "rngR":
            cols["s_rR"][r] = 1
        if d.get("start"):
            cols["s_start"][r] = 1
        if k == "sq":
            cols["t_sq2mul"][r] = 1
        if k == "mul" and nx in ("sq", "ferm"):
            cols["t_mul2x"][r] = 1
        if k == "mul" and nx == "bez":
            cols["t_mul2bez"][r] = 1
        cols["t_tm"][r] = cols["t_mul2x"][r] + cols["t_mul2bez"][r]
        if k == "ferm" and d["chk"] == "m":
            cols["t_ferm2bez"][r] = 1
            cols["s_chk_m"][r] = 1
        if k == "ferm" and d["chk"] == "q":
            cols["s_chk_q"][r] = 1
        if k == "bez" and d["which"] == 3:
            cols["t_bez2e3"][r] = 1
            cols["s_chk_2r"][r] = 1
        if k == "rngG" or k == "sq" or (k == "mul" and not d["lastmul"]):
            cols["t_holdG"][r] = 1
        if k not in ("mimc", "end") and not d.get("last"):
            cols["t_reg"][r] = 1
        if d.get("last") and d["tier"] < T - 1:
            cols["t_tier"][r] = 1
        if d.get("first"):
            cols["s_rel"][r] = 1
        if k == "mimc":
            if d["r"] < MIMC_ROUNDS:
                cols["s_mimc"][r] = 1
                cols["kc"][r] = KC[d["r"]]
                cols["t_mimcH"][r] = 1
            if d["r"] == 0:
                cols["s_mstart"][r] = 1
            if d["r"] == MIMC_ROUNDS:
                cols["s_mend"][r] = 1
                cols["t_commit"][r] = 1
    return cols


# ============================================================================ the AIR
_NAMES = []


def _constraints(c, n, p, names=None):
    (s_mm, s_bez, s_sqf, s_mul, s_ferm, s_rG, s_rT, s_rR, s_start, t_sq2mul, t_mul2x, t_mul2bez, t_tm, t_ferm2bez,
     t_bez2e3, t_holdG, t_reg, t_tier, s_rel, s_chk_m, s_chk_2r, s_chk_q, s_mimc, kc, s_mstart, s_mend, t_mimcH,
     t_commit) = p
    A, B, Q, V, G, EB, EA, N, QR, RR, MM, S_, U, KEY, MSG, CM = c[:16]
    out = []

    def add(name, val):
        out.append(val % P)
        if names is not None:
            names.append(name)

    for i in range(WB):
        b = c[BQ0 + i]
        add("bool_Q", b * (b - 1))
    for i in range(WB):
        b = c[BV0 + i]
        add("bool_V", b * (b - 1))
    add("recomp_Q", Q - sum(c[BQ0 + i] << i for i in range(WB)))
    add("recomp_V", V - sum(c[BV0 + i] << i for i in range(WB)))
    AB = A * B
    add("modmul", s_mm * (AB - Q * N - V))
    add("bezout_eq", s_bez * (AB - Q * N - 1))
    add("bezout_w_is_V", s_bez * (B - V))
    add("square_B_eq_A", s_sqf * (B - A))
    add("mul_B_is_base", s_mul * (B - G))
    add("fermat_remainder_1", s_ferm * (V - 1))
    add("range_base", s_rG * (V - G))
    add("range_slack_q", s_rT * (V - (2 * QR - 1 - RR)))
    add("range_R_ge_1", s_rR * (V - (RR - 1)))
    add("bit_boolean", s_mul * EB * (EB - 1))
    add("ladder_start_A", s_start * (A - 1))
    add("ladder_start_EA", s_start * EA)
    add("sq_to_mul_A", t_sq2mul * (n[0] - V))
    add("sq_to_mul_EA", t_sq2mul * (n[6] - 2 * EA - n[5]))
    xnext = A + EB * (V - A)
    add("mul_to_next_A", t_mul2x * (n[0] - xnext))
    add("mul_to_bez_A", t_mul2bez * (n[0] - xnext + 1))
    add("mul_to_next_EA", t_tm * (n[6] - EA))
    add("ferm_to_bez_A", t_ferm2bez * (n[0] - A + 1))
    add("bez_to_ladder3_G", t_bez2e3 * (n[4] - A - 1))
    add("hold_G", t_holdG * (n[4] - G))
    add("hold_N", t_reg * (n[7] - N))
    add("hold_QR", t_reg * (n[8] - QR))
    add("hold_RR", t_reg * (n[9] - RR))
    add("hold_MM", t_reg * (n[10] - MM))
    add("tier_link_n_is_q", t_tier * (n[7] - QR))
    add("n_is_2m_plus_1", s_rel * (N - 2 * MM - 1))
    add("m_is_qR", s_rel * (QR * RR - MM))
    add("exp_is_m", s_chk_m * (EA - MM))
    add("exp_is_2R", s_chk_2r * (EA - 2 * RR))
    add("exp_is_q", s_chk_q * (EA - QR))
    T = S_ + KEY + kc
    add("mimc_square", s_mimc * (U - T * T))
    add("mimc_cube", s_mimc * (n[11] - U * T))
    add("mimc_start", s_mstart * (S_ - MSG))
    add("mimc_end", s_mend * (CM - S_ - KEY - MSG))
    add("hold_KEY", t_mimcH * (n[13] - KEY))
    add("hold_MSG", t_mimcH * (n[14] - MSG))
    add("commit_to_n", t_commit * (n[7] - MSG))
    return out


class PrimeAIR(S.AIR):
    width = WIDTH
    degree = 3

    def __init__(self, cm, profile=PROFILE):
        self.profile = tuple(profile)
        self.cm = cm
        self.desc, self.first_rows = layout(self.profile)
        self.n_real = len(self.desc)
        names = []
        z = [0] * WIDTH
        _constraints(z, z, [0] * len(PUBN), names)
        self.names = names
        self.n_constraints = len(names)
        self.boundary = [(IDX["CM"], MIMC_ROUNDS, cm), (IDX["QR"], self.first_rows[-1], 3)]
        self._pub = {}

    def pub_columns(self, N):
        if N not in self._pub:
            t = pub_table(self.desc, self.profile, N)
            self._pub[N] = [t[n] for n in PUBN]
        return self._pub[N]

    def transition(self, cur, nxt, pub):
        return _constraints(cur, nxt, pub)

    def extra(self):
        return b"stark_primality|v1|" + repr(self.profile).encode()


# ============================================================================ witness
def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def make_chain(profile=PROFILE, rng=None, forced_R=None, terminal=3, forced_q=None):
    """Random certified prime following the size profile, built bottom-up. forced_R={tier: R} and forced_q={tier: q}
    (use a q that is NOT the next tier's n) are for forgery tests."""
    rng = rng or secrets.SystemRandom()
    T = len(profile)
    chain = [None] * T
    q = terminal
    for i in range(T - 1, -1, -1):
        if forced_q and i in forced_q:
            q = forced_q[i]
        Rmax = min(2 * q - 1, ((1 << profile[i]) - 2) // (2 * q))
        if forced_R and i in forced_R:
            R = forced_R[i]
            n = 2 * q * R + 1
        else:
            lo = max(1, Rmax // 2)
            while True:
                R = rng.randrange(lo, Rmax + 1)
                n = 2 * q * R + 1
                if is_prime(n):
                    break
                lo = max(1, lo - 1) if rng.randrange(8) == 0 else lo
        chain[i] = {"n": n, "q": q, "R": R}
        q = n
    return chain


def find_bases(n, q):
    a2 = next((a for a in range(2, 2000) if pow(a, (n - 1) // 2, n) == n - 1), 2)
    aq = next((a for a in range(2, 2000) if (n - 1) % q == 0 and pow(a, (n - 1) // q, n) != 1), 2)
    return a2, aq


def build_rows(chain, salt, profile=PROFILE, cheat=None):
    """Execution trace of the honest prover. `cheat` is a TEST HOOK: a dict that makes the builder emit a forged trace
    that is internally consistent except for ONE family of constraints (see _single_family_cheats in the self-test).
    Keys: tier; exp {blk: exponent}; ea0 {blk: start of the exponent register}; x0 {blk: start cell};
    jump_hold / jump_sqmul {blk: (step, jump)}; ebj {blk: {step: j}} (non-boolean bit EB = bit + j n);
    shift3 (1: base of block 3 is yq + n, 2: also the Bezout cell); R_mult, mm_follows; mimc {key0, s0, msg, cm,
    u_tamper, cube_tamper}."""
    ch = cheat or {}
    desc, _ = layout(profile)
    rows = [[0] * WIDTH for _ in desc]
    ri = 0
    n0 = chain[0]["n"]
    mc = ch.get("mimc", {})
    msg = mc.get("msg", n0)
    s = mc.get("s0", msg) % P
    for r in range(MIMC_ROUNDS + 1):
        row = rows[ri]
        key = mc.get("key0", salt) if r == 0 else salt
        row[IDX["S"]], row[IDX["KEY"]], row[IDX["MSG"]] = s, key, msg
        if r < MIMC_ROUNDS:
            t = (s + key + KC[r]) % P
            u = t * t % P
            if mc.get("u_tamper", (None,))[0] == r:
                u = mc["u_tamper"][1] % P
            row[IDX["U"]] = u
            s = u * t % P
            if mc.get("cube_tamper", (None,))[0] == r:
                s = mc["cube_tamper"][1] % P
        else:
            row[IDX["CM"]] = mc["cm"] % P if "cm" in mc else (s + key + msg) % P
        ri += 1

    def setbits(row, base, v):
        if 0 <= v < (1 << WB):
            for i in range(WB):
                row[base + i] = (v >> i) & 1

    def put(kind, regs, **vals):
        nonlocal ri
        assert desc[ri]["k"] == kind, (ri, desc[ri], kind)
        row = rows[ri]
        for k_, v_ in regs.items():
            row[IDX[k_]] = v_ % P
        for k_, v_ in vals.items():
            row[IDX[k_]] = v_ % P
        for k_ in ("Q", "V"):
            base = BQ0 if k_ == "Q" else BV0
            setbits(row, base, row[IDX[k_]])
        ri += 1
        return row

    for i, t in enumerate(chain):
        n, q, R = t["n"], t["q"], t["R"]
        c = ch if ch.get("tier") == i else {}
        Ru = R * c.get("R_mult", 1)                      # the R the forged trace uses (honest: R)
        m_true = q * R
        MMreg = q * Ru if c.get("mm_follows") else m_true
        L1, L2, L3 = tier_bits(profile, i)
        regs = {"N": n, "QR": q, "RR": Ru, "MM": MMreg}
        a2, aq = find_bases(n, q)

        def ladder(blk, base, e, L):
            ea = c.get("ea0", {}).get(blk, 0) % P
            xc = c.get("x0", {}).get(blk, 1)
            ebj = c.get("ebj", {}).get(blk, {})
            jh = c.get("jump_hold", {}).get(blk)
            js = c.get("jump_sqmul", {}).get(blk)
            for b in range(L):
                bit = (e >> (L - 1 - b)) & 1
                u = (xc % n) * (xc % n) % n
                put("sq", regs, A=xc, B=xc, V=u, Q=(xc * xc - u) // n, EA=ea, G=base)
                mm = u * base % n
                eb = bit + ebj.get(b, 0) * n
                ea = (2 * ea + eb) % P
                if js and js[0] == b:
                    ea = (ea + js[1]) % P
                put("mul", regs, A=u, B=base, V=mm, Q=(u * base - mm) // n, EA=ea, EB=eb, G=base)
                xc = u + eb * (mm - u)                   # exact integers (honest: u or mm)
                if jh and jh[0] == b:
                    ea = (ea + jh[1]) % P
            return xc, ea

        exps = c.get("exp", {})
        put("rngG", regs, V=a2, G=a2)
        y2, ea = ladder(1, a2, exps.get(1, MMreg), L1)
        put("ferm", regs, A=y2, B=y2, V=1, Q=y2 * y2 // n, EA=ea)
        w2 = pow(y2 - 1, -1, n) if (y2 - 1) % n and __import__("math").gcd(y2 - 1, n) == 1 else 0
        put("bez", regs, A=y2 - 1, B=w2, V=w2, Q=((y2 - 1) * w2 - 1) // n)
        put("rngG", regs, V=aq, G=aq)
        yq, ea = ladder(2, aq, exps.get(2, 2 * Ru), L2)
        wq = pow(yq - 1, -1, n) if (yq - 1) % n and __import__("math").gcd(yq - 1, n) == 1 else 0
        sh = c.get("shift3", 0)
        Ab = yq - 1 + (n if sh == 2 else 0)
        put("bez", regs, A=Ab, B=wq, V=wq, Q=(Ab * wq - 1) // n, EA=ea)
        y3, ea = ladder(3, yq + (n if sh else 0), exps.get(3, q), L3)
        put("ferm", regs, A=y3, B=y3, V=1, Q=y3 * y3 // n, EA=ea)
        put("rngT", regs, V=2 * q - 1 - Ru)
        put("rngR", regs, V=Ru - 1)
    assert ri == len(rows) - 1
    return rows


def check_trace(air, rows):
    """Direct evaluation of every constraint on the (unpadded) rows. Returns {constraint name: [rows violated]}."""
    pub = pub_table(air.desc, air.profile, len(rows) + 1)
    bad = {}
    for r in range(len(rows) - 1):
        p = [pub[nm][r] for nm in PUBN]
        vals = _constraints(rows[r], rows[r + 1], p)
        for nm, v in zip(air.names, vals):
            if v:
                bad.setdefault(nm, []).append(r)
    for c, r, v in air.boundary:
        if rows[r][c] % P != v % P:
            bad.setdefault("boundary", []).append(r)
    return bad


# ============================================================================ API
def prove_prime(chain, salt=None, profile=PROFILE, _force=False):
    salt = secrets.randbelow(P) if salt is None else salt
    rows = build_rows(chain, salt, profile)
    cm = commit(chain[0]["n"], salt)
    air = PrimeAIR(cm, profile)
    return cm, S.prove(air, rows, _force=_force)


def verify_prime(cm, proof, profile=PROFILE):
    if type(cm) is not int or not (0 <= cm < P):
        return False
    return S.verify(PrimeAIR(cm, profile), proof)


# ============================================================================ self-test
def _selftest():
    import copy
    import random
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}", flush=True)
        if not ok:
            failures.append(name)

    desc, first_rows = layout()
    N = S.trace_len(PrimeAIR(0))
    print(f"profile {PROFILE}: {len(desc)} real rows, trace length N = {N}, width {WIDTH}, "
          f"{PrimeAIR(0).n_constraints} constraints, degree 3")
    rng = random.Random(secrets.randbits(64))

    print("\n1) an honest witness satisfies every constraint")
    chain = make_chain(rng=rng)
    n0 = chain[0]["n"]
    print(f"    n = {n0} ({n0.bit_length()} bits), chain {[t['n'] for t in chain]}")
    salt = secrets.randbelow(P)
    rows = build_rows(chain, salt)
    cm = commit(n0, salt)
    air = PrimeAIR(cm)
    check("no constraint violated on the honest trace", check_trace(air, rows), {})
    check("n is prime (independent test)", is_prime(n0))
    check("chain links: every q is the next n", all(chain[i]["q"] == chain[i + 1]["n"] for i in range(4)) and chain[-1]["q"] == 3)

    print("\n2) every load-bearing cell matters: mutate one cell, expect a violation")
    used = {
        "mimc": {"S", "U", "KEY", "MSG", "Q", "V"},
        "rngG": {"V", "G", "N", "QR", "RR", "MM", "Q"},
        "sq": {"A", "B", "Q", "V", "EA", "G", "N", "QR", "RR", "MM"},
        "mul": {"A", "B", "Q", "V", "EB", "EA", "G", "N", "QR", "RR", "MM"},
        "ferm": {"A", "B", "Q", "V", "EA", "N", "QR", "RR", "MM"},
        "bez": {"A", "B", "Q", "V", "N", "QR", "RR", "MM"},
        "rngT": {"V", "N", "QR", "RR", "MM", "Q"},
        "rngR": {"V", "N", "QR", "RR", "MM", "Q"},
    }
    by_kind = {}
    for r, d in enumerate(desc[:-1]):
        by_kind.setdefault(d["k"], []).append(r)
    undetected_used, tested = [], 0
    pub = pub_table(desc, PROFILE, len(rows) + 1)
    for kind, rl in by_kind.items():
        for r in rng.sample(rl, min(len(rl), 8)):
            cols = [c for c in range(WIDTH)]
            for c in cols:
                name = COLS[c] if c < BQ0 else ("BQ" if c < BV0 else "BV")
                row = rows[r]
                old = row[c]
                row[c] = (old + 1) % P
                lo = max(0, r - 1)
                hit = False
                for rr in range(lo, min(r + 1, len(rows) - 2) + 1):
                    p = [pub[nm][rr] for nm in PUBN]
                    if any(_constraints(rows[rr], rows[rr + 1], p)):
                        hit = True
                        break
                row[c] = old
                tested += 1
                if name in ("BQ", "BV"):
                    continue
                extra_used = name in used.get(kind, set()) or (kind == "mimc" and name == "CM" and desc[r]["r"] == MIMC_ROUNDS)
                if kind == "bez" and name == "EA" and desc[r]["which"] == 3:
                    extra_used = True
                if kind == "mimc" and name == "U" and desc[r]["r"] == MIMC_ROUNDS:
                    extra_used = False
                if kind == "ferm" and name == "G":
                    extra_used = False
                if extra_used and not hit:
                    undetected_used.append((kind, name, r))
    check(f"every load-bearing cell is tied down ({tested} mutations tried)", undetected_used, [])
    if undetected_used:
        print("    undetected:", undetected_used[:10])
    # bit cells: flipping a bit of Q or V must be caught everywhere (recomposition)
    flips_missed = 0
    for r in rng.sample(range(len(rows) - 1), 60):
        for c in (BQ0 + rng.randrange(WB), BV0 + rng.randrange(WB)):
            old = rows[r][c]
            rows[r][c] = old ^ 1
            hit = any(any(_constraints(rows[rr], rows[rr + 1], [pub[nm][rr] for nm in PUBN]))
                      for rr in range(max(0, r - 1), r + 1))
            rows[r][c] = old
            flips_missed += not hit
    check("flipping any sampled range-check bit is caught", flips_missed, 0)

    print("\n3) forged certificates violate the constraints (which ones is shown)")

    def forged(label, chain_f, salt_f=None, profile=PROFILE):
        salt_f = salt if salt_f is None else salt_f
        rows_f = build_rows(chain_f, salt_f, profile)
        air_f = PrimeAIR(commit(chain_f[0]["n"], salt_f), profile)
        bad = check_trace(air_f, rows_f)
        print(f"    {label}: violated {sorted(bad)}")
        return bad, rows_f, air_f

    # composite top number: take a valid tier and a deliberately composite n_0 = 2 q R + 1
    ch = copy.deepcopy(chain)
    q0 = ch[0]["q"]
    while True:
        R0 = rng.randrange(ch[0]["R"] // 2 + 1, ch[0]["R"] + 1)
        if not is_prime(2 * q0 * R0 + 1) and 2 * q0 * R0 + 1 < (1 << 64):
            break
    ch[0] = {"n": 2 * q0 * R0 + 1, "q": q0, "R": R0}
    bad_c, rows_c, air_c = forged("composite n_0", ch)
    check("composite n_0 is rejected (Fermat or Bezout fails)", bool(bad_c))
    # R too large although n is prime (n > 4 q^2): tier 3 with q = n_4 = 7 and R = 14 > 2q - 1 = 13, n_3 = 197
    ch = make_chain(rng=rng, forced_R={4: 1, 3: 14})
    assert ch[3]["n"] == 197 and is_prime(197) and ch[3]["R"] > 2 * ch[3]["q"] - 1
    bad_r, rows_r, air_r = forged("R = 14 > 2q - 1 with prime n_3 = 197", ch)
    check("R > 2q - 1 (prime n, valid Fermat and Bezout) is rejected, caught by the range-bit recomposition",
          sorted(bad_r), ["recomp_V"])
    # terminal prime other than 3
    ch = make_chain(rng=rng, terminal=5)
    bad_t, _, _ = forged("terminal q = 5", ch)
    check("a chain that ends at 5 instead of 3 is rejected", "boundary" in bad_t)
    # wrong commitment (different salt than the trace was built with)
    air_w = PrimeAIR(commit(n0, (salt + 1) % P))
    check("trace checked against a commitment of another salt is rejected", "boundary" in check_trace(air_w, rows))
    # broken link: q of tier 2 is not the next n
    ch = copy.deepcopy(chain)
    ch[2]["q"] = ch[3]["n"] + 2 * ch[3]["n"]            # q != n_3
    ch[2]["n"] = 2 * ch[2]["q"] * ch[2]["R"] + 1
    bad_l, _, _ = forged("tier 2 uses a q that is not the next tier's n", ch)
    check("broken tier link is rejected", "tier_link_n_is_q" in bad_l or bool(bad_l))
    # a prime factor replaced by an uncertified composite q' (tier 2 is internally valid, its q' is just not
    # the n certified by tier 3): only the tier link can catch this
    qc = next(x for x in range(200, 512) if not is_prime(x) and x % 2 == 1)
    ch = make_chain(rng=rng, forced_q={2: qc})
    bad_k, _, _ = forged(f"tier 2 built on the composite q' = {qc} (a skipped factorisation)", ch)
    check("a skipped factorisation is caught by the tier link alone", sorted(bad_k), ["tier_link_n_is_q"])
    # out-of-range base (wrap attack)
    rows_b = copy.deepcopy(rows)
    r_g = by_kind["rngG"][0]
    rows_b[r_g][IDX["G"]] = (rows_b[r_g][IDX["G"]] + (1 << 70)) % P
    rows_b[r_g][IDX["V"]] = rows_b[r_g][IDX["G"]]
    check("a base above 2^64 is rejected by the range check", bool(check_trace(air, rows_b)))

    print("\n3b) one forged trace per constraint, each violating exactly that constraint")
    cheats = _single_family_cheats(rng)
    names = sorted(set(PrimeAIR(0).names))
    for nm in names:
        check(f"{nm}: the forged trace violates exactly this constraint", cheats.get(nm), {nm})
    check("every constraint of the AIR has such a forged trace", sorted(cheats), names)

    print("\n4) end to end: prove and verify")
    t0 = time.time()
    cm_, proof = prove_prime(chain, salt)
    t_prove = time.time() - t0
    t0 = time.time()
    ok = verify_prime(cm_, proof)
    t_ver = time.time() - t0
    check("honest proof accepted", ok)
    print(f"    prove {t_prove:.1f} s, verify {t_ver:.2f} s, proof {S.proof_size_bytes(proof) / 1024:.0f} KiB")
    check("commitment matches commit(n, salt)", cm_ == commit(n0, salt))
    check("proof checked against another commitment: rejected", verify_prime((cm_ + 1) % P, proof), False)
    check("proof checked against another profile: rejected", verify_prime(cm_, proof, profile=(64, 33, 17, 9, 6)), False)
    check("the honest prover refuses a forged chain (composite n_0)",
          _refuses(lambda: S.prove(air_c, rows_c)))
    check("a forced proof of the composite n_0 is rejected", verify_prime(air_c.cm, S.prove(air_c, rows_c, _force=True)), False)
    check("a forced proof with R > 2q - 1 is rejected", verify_prime(air_r.cm, S.prove(air_r, rows_r, _force=True)), False)
    blob = repr(proof).encode()
    check("n and the salt do not appear in the proof", str(n0).encode() not in blob and str(salt).encode() not in blob)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy STARK + home-made algebraic commitment; soundness conjectured, zero knowledge argued; unaudited.")
    return 1 if failures else 0


def _single_family_cheats(rng):
    """One forged trace per constraint, each violating EXACTLY that constraint (all others hold). Returns
    {name: set of violated constraint names}. If a constraint is removed from the AIR, the cheat built for it
    becomes a valid-looking trace, so the assertion in the self-test fails: this is the removal check, made
    permanent. The cheats are real attacks (wrong exponent, forged commitment, non-boolean bit, ...)."""
    desc, _ = layout()

    def small_chain():
        for _ in range(500):
            seed = rng.getrandbits(64)
            c0 = make_chain(rng=random.Random(seed))
            q = c0[3]["q"]
            if q == 3 or q > 15:
                continue
            Rs = next((R for R in range(1, (2 * q - 1) // 3 + 1) if is_prime(2 * q * R + 1)), None)
            if Rs is None or 3 * q * Rs >= 255 or 6 * Rs >= 128:
                continue
            return make_chain(rng=random.Random(seed), forced_R={3: Rs})
        raise RuntimeError("no small chain found")

    chain = small_chain()
    n3, q3, R3 = chain[3]["n"], chain[3]["q"], chain[3]["R"]
    m3 = q3 * R3
    L1, L2, L3 = tier_bits(PROFILE, 3)
    inv2 = lambda e: pow(pow(2, e, P), -1, P)
    salt = secrets.randbelow(P)
    out = {}

    def run(name, cheat=None, edit=None, chain_c=None):
        rows = build_rows(chain_c or chain, salt, PROFILE, cheat)
        if edit:
            edit(rows)
        air = PrimeAIR(rows[MIMC_ROUNDS][IDX["CM"]])
        out[name] = set(check_trace(air, rows))

    def rowsof(kind, tier=3, **flt):
        return [r for r, d in enumerate(desc[:-1]) if d["k"] == kind and d.get("tier") == tier
                and all(d.get(k) == v for k, v in flt.items())]

    def setc(rows, r, name, v):
        row = rows[r]
        row[IDX[name]] = v % P
        if name in ("Q", "V"):
            base = BQ0 if name == "Q" else BV0
            vv = row[IDX[name]]
            for i in range(WB):
                row[base + i] = (vv >> i) & 1 if vv < (1 << WB) else 0

    def getc(rows, r, name):
        return rows[r][IDX[name]]

    # ---- edits of one row (the cell is changed together with whatever keeps the other constraints true)
    def e_bool(base):
        def f(rows):
            r = rowsof("sq")[2]
            rows[r][base] = (rows[r][base] + 2) % P            # b0 + 2 and b1 - 1 keep the recomposition
            rows[r][base + 1] = (rows[r][base + 1] - 1) % P
        return f

    def e_flip(base):
        def f(rows):
            r = rowsof("sq")[2]
            rows[r][base + 5] ^= 1
        return f

    def bump(kind, name, delta, **flt):
        def f(rows):
            r = rowsof(kind, **flt)[0]
            setc(rows, r, name, getc(rows, r, name) + delta)
        return f

    def e_sqB(rows):
        r = rowsof("sq")[3]
        A, Nn = getc(rows, r, "A"), getc(rows, r, "N")
        setc(rows, r, "B", A + Nn)
        setc(rows, r, "Q", getc(rows, r, "Q") + A)

    def e_mulB(rows):
        r = rowsof("mul")[3]
        u, Nn = getc(rows, r, "A"), getc(rows, r, "N")
        setc(rows, r, "B", getc(rows, r, "B") + Nn)
        setc(rows, r, "Q", getc(rows, r, "Q") + u)

    def e_fermV(rows):
        r = rowsof("ferm", chk="m")[0]
        Nn = getc(rows, r, "N")
        setc(rows, r, "V", 1 + Nn)
        setc(rows, r, "Q", getc(rows, r, "Q") - 1)

    def e_sq2mulA(rows):
        r = next(r for r in rowsof("mul") if getc(rows, r, "EB") == 1)
        Nn = getc(rows, r, "N")
        setc(rows, r, "A", getc(rows, r, "A") + Nn)
        setc(rows, r, "Q", getc(rows, r, "Q") + getc(rows, r, "B"))

    def e_ferm2bez(rows):
        r = rowsof("bez", which=2)[0]
        Nn = getc(rows, r, "N")
        setc(rows, r, "A", getc(rows, r, "A") + Nn)
        setc(rows, r, "Q", getc(rows, r, "Q") + getc(rows, r, "B"))

    def e_mul2nextA(rows):
        r = next(r for r in rowsof("mul", lastmul=False) if desc[r + 1]["k"] == "sq")
        x, Nn = getc(rows, r + 1, "A"), getc(rows, r + 1, "N")
        setc(rows, r + 1, "A", x + Nn)
        setc(rows, r + 1, "B", x + Nn)
        setc(rows, r + 1, "Q", getc(rows, r + 1, "Q") + 2 * x + Nn)

    run("bool_Q", edit=e_bool(BQ0))
    run("bool_V", edit=e_bool(BV0))
    run("recomp_Q", edit=e_flip(BQ0))
    run("recomp_V", edit=e_flip(BV0))
    run("modmul", edit=bump("ferm", "Q", 1, chk="m"))
    run("bezout_eq", edit=bump("bez", "Q", 1, which=2))
    run("bezout_w_is_V", edit=bump("bez", "V", 1, which=2))
    run("square_B_eq_A", edit=e_sqB)
    run("mul_B_is_base", edit=e_mulB)
    run("fermat_remainder_1", edit=e_fermV)
    run("range_base", edit=bump("rngG", "V", 1))
    run("range_slack_q", edit=bump("rngT", "V", 1))
    run("range_R_ge_1", edit=bump("rngR", "V", 1))
    run("sq_to_mul_A", edit=e_sq2mulA)
    run("ferm_to_bez_A", edit=e_ferm2bez)
    run("mul_to_next_A", edit=e_mul2nextA)
    run("hold_G", edit=bump("sq", "G", 1))
    run("hold_N", edit=bump("rngT", "N", 1))
    run("hold_QR", edit=bump("bez", "QR", 1, which=2))
    run("hold_RR", edit=bump("ferm", "RR", 1, chk="m"))
    run("hold_MM", edit=bump("bez", "MM", 1, which=2))

    def e_msg(rows):
        rows[50][IDX["MSG"]] = (rows[50][IDX["MSG"]] + 1) % P
    run("hold_MSG", edit=e_msg)

    # ---- forged ladders and registers (the builder keeps everything else consistent)
    e3 = 3 * m3                                                # a wrong exponent that still gives y = -1
    run("exp_is_m", {"tier": 3, "exp": {1: e3}})
    run("exp_is_2R", {"tier": 3, "exp": {2: 6 * R3}})
    run("exp_is_q", {"tier": 3, "exp": {3: 2 * q3}})
    run("ladder_start_A", {"tier": 3, "x0": {1: n3 - 1}})
    run("ladder_start_EA", {"tier": 3, "exp": {1: e3}, "ea0": {1: (m3 - e3) * inv2(L1) % P}})
    k = 2
    jmp = (m3 - e3) * inv2(L1 - 1 - k) % P
    run("mul_to_next_EA", {"tier": 3, "exp": {1: e3}, "jump_hold": {1: (k, jmp)}})
    run("sq_to_mul_EA", {"tier": 3, "exp": {1: e3}, "jump_sqmul": {1: (k, jmp)}})
    run("bez_to_ladder3_G", {"tier": 3, "shift3": 1})
    run("mul_to_bez_A", {"tier": 3, "shift3": 2})
    run("m_is_qR", {"tier": 3, "R_mult": 3})
    run("n_is_2m_plus_1", {"tier": 3, "R_mult": 3, "mm_follows": True})
    # two non-boolean bits (1 + n and -2n) that cancel in the exponent register: an affine step x' = u + EB (mm - u)
    big = make_chain(rng=rng)
    run("bit_boolean", {"tier": 2, "ebj": {1: {1: 1, 2: -2}}}, chain_c=big)

    # ---- the algebraic commitment
    n0 = chain[0]["n"]
    run("hold_KEY", {"mimc": {"key0": (salt + 1) % P}})
    run("mimc_start", {"mimc": {"s0": n0 + 1}})
    run("mimc_square", {"mimc": {"u_tamper": (10, 12345)}})
    run("mimc_cube", {"mimc": {"cube_tamper": (10, 777)}})
    run("mimc_end", {"mimc": {"cm": 99}})
    run("commit_to_n", {"mimc": {"msg": n0 + 2}})

    # ---- a q that is not the next tier's n (a skipped factorisation)
    qc = next(x for x in range(200, 512) if not is_prime(x) and x % 2 == 1)
    run("tier_link_n_is_q", chain_c=make_chain(rng=rng, forced_q={2: qc}))
    return out



def _refuses(fn):
    try:
        fn()
        return False
    except S.ProverError:
        return True


if __name__ == "__main__":
    sys.exit(_selftest())
