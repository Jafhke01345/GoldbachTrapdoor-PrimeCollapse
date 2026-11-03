"""
stark_primality.py - a STARK (hash-based, see stark_core.py) that a COMMITTED number n below 2^64 is prime, via a
recursive Pocklington certificate that stays hidden. Nothing is opened: not n, not q, R, the bases or the Bezout
witnesses, and not the blinding scalar.

    Public    : C = n*G + s*H, a Pedersen commitment on the Stark elliptic curve (see stark_curve.py)
                the size profile (bit bounds of n_0 > n_1 > ... , default (64, 33, 17, 9, 5)) and the terminal prime 3
    Witness   : n = n_0, the scalar s, and for each tier i: n_i = 2 q_i R_i + 1, q_i = n_{i+1} (q of the last tier is
                3), bases a2_i, aq_i and Bezout witnesses w2_i, wq_i
    The AIR enforces, for every tier (all arithmetic is modular multiplication gadgets with 64-bit range checks):
        n = 2 q R + 1 over the integers and q*R computed exactly; 1 <= R <= 2q - 1 (so 4 q^2 > n);
        y2 = a2^((n-1)/2) with y2^2 = 1 (mod n) and (y2 - 1) w2 = 1 (mod n);
        yq = aq^((n-1)/q) with yq^(2q) = 1 (mod n) and (yq - 1) wq = 1 (mod n);
        n_{i+1} = q_i, the chain ends at q = 3, and C = n_0*G + s*H.
    Each n_i is then prime, hence n_0 is. The factor-2 rows are Pocklington's conditions as usual. For the factor q the
    circuit checks the WEAKER Fermat form yq^(2q) = 1 (the final row squares y = yq^q and compares with 1), not yq^q = 1.
    That is still sufficient, by this short argument rather than by Pocklington's theorem as stated: let q be an odd prime,
    n = 2qR + 1 with 1 <= R <= 2q - 1, and suppose gcd(yq - 1, n) = 1 and yq^(2q) = 1 (mod n) with yq = aq^(2R). For a prime
    p | n the order of yq modulo p divides 2q and is not 1, so it is 2, q or 2q. (a) If it is q or 2q then q | p - 1, so
    p >= 2q + 1. (b) If it is 2 then yq = -1 (mod p), so aq^(2R) = -1 and the 2-adic valuation of ord(aq) is v2(R) + 2, hence
    2^(v2(R)+2) | p - 1. If no prime divisor were of type (a), then n = 1 (mod 2^(v2(R)+2)), contradicting
    v2(n - 1) = v2(R) + 1. So some prime divisors are of type (a); let N1 be the product of the type-(a) prime powers
    (N1 = 1 mod q, N1 >= 2q + 1) and M = n / N1 the rest. Then M = 1 (mod q) and M < n / (2q + 1) < 2q, M odd, so M = 1.
    Every prime divisor of n is of type (a), so a composite n would be at least (2q + 1)^2 > 4q^2 > n. Hence n is prime.
    The self-test checks this claim exhaustively for every odd prime q <= 41 (every R and every base).

Exponents are hidden: every exponentiation is a square-and-multiply ladder whose bits are witness columns,
accumulated into a register that is compared with the hidden number it must equal.

THE COMMITMENT IS INSIDE THE CIRCUIT. The curve's coordinates are elements of the STARK field, so a point addition is
native field arithmetic. 252 rows run a double-and-add: each row doubles the accumulator, adds G when the bit of n is
set (only in the last 64 rows, so n cannot wrap), adds H when the bit of s is set. The accumulator starts at a hashed
point D, which keeps the "point at infinity" corner cases out of the formulas, and each addition proves its two
x-coordinates differ with a witness inverse, so a degenerate step cannot be forged. The final point must equal the
public C + 2^252 D, and the register that collected the bits of n must equal the n at the top of the chain.
This replaces an earlier home-made MiMC hash: the commitment is now binding under the elliptic-curve discrete log and
can be tied to the Pedersen commitment of the rest of the repository by a small sigma protocol (link_commitments.py).

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
import stark_curve as SC

P = S.P
assert SC.P == P, "the curve's base field must be the STARK field"
PROFILE = (64, 33, 17, 9, 5)
EC_BITS = 252                                            # scalar width of the in-circuit double-and-add
EC_G_BITS = 64                                           # only the last 64 rows may add G (n < 2^64, no wrap)
ECEND = EC_BITS                                          # index of the row that holds the final point
WB = 64                                                  # range-check width
COLS = ["A", "B", "Q", "V", "G", "EB", "EA", "N", "QR", "RR", "MM",
        "AX", "AY", "L1", "TX", "TY", "L2", "I2", "WX", "WY", "VX", "VY", "L3", "I3", "XX", "XY", "BN", "BS", "EN"]
IDX = {c: i for i, c in enumerate(COLS)}
BQ0 = len(COLS)
BV0 = BQ0 + WB
WIDTH = BV0 + WB
PUBN = ["s_mm", "s_bez", "s_sqf", "s_mul", "s_ferm", "s_rG", "s_rT", "s_rR", "s_start", "t_sq2mul", "t_mul2x",
        "t_mul2bez", "t_tm", "t_ferm2bez", "t_bez2e3", "t_holdG", "t_reg", "t_tier", "s_rel", "s_chk_m", "s_chk_2r",
        "s_chk_q", "s_ec", "s_ecG", "s_ecst", "t_ecn"]


# ============================================================================ commitment
def commit(n, scalar):
    """The public commitment: the point n*G + scalar*H on the Stark curve."""
    return SC.commit(n, scalar)


def end_point(C):
    """The point the accumulator must hold on the last row: C + 2^252 * D (D is the in-circuit start point)."""
    return SC.add(C, SC.mul(pow(2, EC_BITS, SC.Q), SC.D))


def tier_bits(profile, i):
    """(bits of (n-1)/2, bits of 2R, bits of q) for tier i."""
    Bn = profile[i]
    Bq = profile[i + 1] if i + 1 < len(profile) else 2
    return Bn - 1, Bq + 2, Bq


def layout(profile=PROFILE):
    d = []
    for r in range(EC_BITS):
        d.append({"k": "ec", "r": r, "tier": None})
    d.append({"k": "ecend", "tier": None})
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
        if k not in ("ec", "ecend", "end") and not d.get("last"):
            cols["t_reg"][r] = 1
        if d.get("last") and d["tier"] < T - 1:
            cols["t_tier"][r] = 1
        if d.get("first"):
            cols["s_rel"][r] = 1
        if k == "ec":
            cols["s_ec"][r] = 1
            if d["r"] >= EC_BITS - EC_G_BITS:
                cols["s_ecG"][r] = 1
            if d["r"] == 0:
                cols["s_ecst"][r] = 1
        if k == "ecend":
            cols["t_ecn"][r] = 1
    return cols


# ============================================================================ the AIR
_NAMES = []


def _constraints(c, n, p, names=None):
    (s_mm, s_bez, s_sqf, s_mul, s_ferm, s_rG, s_rT, s_rR, s_start, t_sq2mul, t_mul2x, t_mul2bez, t_tm, t_ferm2bez,
     t_bez2e3, t_holdG, t_reg, t_tier, s_rel, s_chk_m, s_chk_2r, s_chk_q, s_ec, s_ecG, s_ecst, t_ecn) = p
    (A, B, Q, V, G, EB, EA, N, QR, RR, MM, AX, AY, L1, TX, TY, L2, I2, WX, WY, VX, VY, L3, I3, XX, XY, BN, BS,
     EN) = c[:BQ0]
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
    # ---- the commitment C = n*G + s*H, one double-and-add step per row (see the docstring)
    Gx, Gy, Hx, Hy = SC.GX, SC.GY, SC.H[0], SC.H[1]
    add("ec_dbl_lam", s_ec * (L1 * 2 * AY - 3 * AX * AX - SC.ALPHA))
    add("ec_dbl_x", s_ec * (TX - (L1 * L1 - 2 * AX)))
    add("ec_dbl_y", s_ec * (TY - (L1 * (AX - TX) - AY)))
    add("ec_G_lam", s_ec * (L2 * (Gx - TX) - (Gy - TY)))
    add("ec_G_inv", s_ec * (I2 * (Gx - TX) - 1))
    add("ec_G_x", s_ec * (WX - (L2 * L2 - TX - Gx)))
    add("ec_G_y", s_ec * (WY - (L2 * (TX - WX) - TY)))
    add("ec_G_selx", s_ec * (VX - (TX + BN * (WX - TX))))
    add("ec_G_sely", s_ec * (VY - (TY + BN * (WY - TY))))
    add("ec_bnG_zero", s_ec * (1 - s_ecG) * BN)
    add("ec_bn_bool", s_ec * BN * (BN - 1))
    add("ec_H_lam", s_ec * (L3 * (Hx - VX) - (Hy - VY)))
    add("ec_H_inv", s_ec * (I3 * (Hx - VX) - 1))
    add("ec_H_x", s_ec * (XX - (L3 * L3 - VX - Hx)))
    add("ec_H_y", s_ec * (XY - (L3 * (VX - XX) - VY)))
    add("ec_H_selx", s_ec * (n[IDX["AX"]] - (VX + BS * (XX - VX))))
    add("ec_H_sely", s_ec * (n[IDX["AY"]] - (VY + BS * (XY - VY))))
    add("ec_bs_bool", s_ec * BS * (BS - 1))
    add("ec_En", s_ec * (n[IDX["EN"]] - 2 * EN - BN))
    add("ec_start_En", s_ecst * EN)
    add("ec_start_ax", s_ecst * (AX - SC.D[0]))
    add("ec_start_ay", s_ecst * (AY - SC.D[1]))
    add("ec_link_n", t_ecn * (n[IDX["N"]] - EN))
    return out


class PrimeAIR(S.AIR):
    width = WIDTH
    degree = 3

    def __init__(self, C, profile=PROFILE):
        self.profile = tuple(profile)
        self.C = C
        self.desc, self.first_rows = layout(self.profile)
        self.n_real = len(self.desc)
        names = []
        z = [0] * WIDTH
        _constraints(z, z, [0] * len(PUBN), names)
        self.names = names
        self.n_constraints = len(names)
        e = end_point(C) if C is not None else (0, 0)
        if e is None:
            raise ValueError("degenerate commitment")
        self.boundary = [(IDX["AX"], ECEND, e[0]), (IDX["AY"], ECEND, e[1]), (IDX["QR"], self.first_rows[-1], 3)]
        self._pub = {}

    def pub_columns(self, N):
        if N not in self._pub:
            t = pub_table(self.desc, self.profile, N)
            self._pub[N] = [t[n] for n in PUBN]
        return self._pub[N]

    def transition(self, cur, nxt, pub):
        return _constraints(cur, nxt, pub)

    def extra(self):
        return b"stark_primality|v2|" + repr((self.profile, SC.G, SC.H, SC.D)).encode()


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


def build_rows(chain, scalar, profile=PROFILE, cheat=None):
    """Execution trace of the honest prover. `cheat` is a TEST HOOK: a dict that makes the builder emit a forged trace
    that is internally consistent except for ONE family of constraints (see _single_family_cheats in the self-test).
    Keys: tier; exp {blk: exponent}; ea0 {blk: start of the exponent register}; x0 {blk: start cell};
    jump_hold / jump_sqmul {blk: (step, jump)}; ebj {blk: {step: j}} (non-boolean bit EB = bit + j n);
    shift3 (1: base of block 3 is yq + n, 2: also the Bezout cell); R_mult, mm_follows;
    ec {n_val (integer used as the G-scalar), start (accumulator start point), en0, bn_vals {row: value},
        bs_vals {row: value}, tamper {(row, cell name): delta}, en_jump (row, delta)}."""
    ch = cheat or {}
    desc, _ = layout(profile)
    rows = [[0] * WIDTH for _ in desc]
    ri = 0
    n0 = chain[0]["n"]
    ec = ch.get("ec", {})
    tam = ec.get("tamper", {})
    nval = ec.get("n_val", n0)
    bn_vals, bs_vals = ec.get("bn_vals", {}), ec.get("bs_vals", {})
    ax, ay = ec.get("start", SC.D)
    en = ec.get("en0", 0) % P
    Gx, Gy, Hx, Hy = SC.GX, SC.GY, SC.H[0], SC.H[1]

    def tw(r, name, v):                                  # value of a cell after the (optional) forgery
        return (v + tam.get((r, name), 0)) % P

    for r in range(EC_BITS):
        row = rows[ri]
        bn = bn_vals.get(r, (nval >> (EC_BITS - 1 - r)) & 1) % P
        bs = bs_vals.get(r, (scalar >> (EC_BITS - 1 - r)) & 1) % P
        ax, ay = ax % P, ay % P
        l1 = tw(r, "L1", (3 * ax * ax + SC.ALPHA) * pow(2 * ay, -1, P))
        tx = tw(r, "TX", l1 * l1 - 2 * ax)
        ty = tw(r, "TY", l1 * (ax - tx) - ay)
        l2 = tw(r, "L2", (Gy - ty) * pow(Gx - tx, -1, P))
        i2 = tw(r, "I2", pow(Gx - tx, -1, P))
        wx = tw(r, "WX", l2 * l2 - tx - Gx)
        wy = tw(r, "WY", l2 * (tx - wx) - ty)
        vx = tw(r, "VX", tx + bn * (wx - tx))
        vy = tw(r, "VY", ty + bn * (wy - ty))
        l3 = tw(r, "L3", (Hy - vy) * pow(Hx - vx, -1, P))
        i3 = tw(r, "I3", pow(Hx - vx, -1, P))
        xx = tw(r, "XX", l3 * l3 - vx - Hx)
        xy = tw(r, "XY", l3 * (vx - xx) - vy)
        for nm, v in (("AX", ax), ("AY", ay), ("L1", l1), ("TX", tx), ("TY", ty), ("L2", l2), ("I2", i2), ("WX", wx),
                      ("WY", wy), ("VX", vx), ("VY", vy), ("L3", l3), ("I3", i3), ("XX", xx), ("XY", xy), ("BN", bn),
                      ("BS", bs), ("EN", en)):
            row[IDX[nm]] = v
        ax = tw(r, "AX_next", vx + bs * (xx - vx))
        ay = tw(r, "AY_next", vy + bs * (xy - vy))
        en = (2 * en + bn) % P
        if ec.get("en_jump") and ec["en_jump"][0] == r:
            en = (en + ec["en_jump"][1]) % P
        ri += 1
    rows[ri][IDX["AX"]], rows[ri][IDX["AY"]], rows[ri][IDX["EN"]] = ax % P, ay % P, en
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
def prove_prime(chain, scalar=None, profile=PROFILE, _force=False):
    """Prove that the n at the top of `chain` is prime. Returns (C, proof) with C = n*G + scalar*H."""
    scalar = secrets.randbits(EC_BITS) if scalar is None else scalar
    rows = build_rows(chain, scalar, profile)
    C = commit(chain[0]["n"], scalar)
    air = PrimeAIR(C, profile)
    return C, S.prove(air, rows, _force=_force)


def verify_prime(C, proof, profile=PROFILE):
    if type(C) is not tuple or len(C) != 2 or not SC.on_curve(C) or C is None or end_point(C) is None:
        return False
    return S.verify(PrimeAIR(C, profile), proof)


# ============================================================================ self-test
def _selftest():
    import copy
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}", flush=True)
        if not ok:
            failures.append(name)

    desc, first_rows = layout()
    air0 = PrimeAIR(None)
    N = S.trace_len(air0)
    print(f"profile {PROFILE}: {len(desc)} real rows, trace length N = {N}, width {WIDTH}, "
          f"{air0.n_constraints} constraints, degree 3")
    rng = random.Random(secrets.randbits(64))

    print("\n1) an honest witness satisfies every constraint")
    chain = make_chain(rng=rng)
    n0 = chain[0]["n"]
    print(f"    n = {n0} ({n0.bit_length()} bits), chain {[t['n'] for t in chain]}")
    scalar = secrets.randbits(EC_BITS)
    rows = build_rows(chain, scalar)
    C = commit(n0, scalar)
    air = PrimeAIR(C)
    check("no constraint violated on the honest trace", check_trace(air, rows), {})
    check("the accumulator ends at C + 2^252 * D", (rows[ECEND][IDX["AX"]], rows[ECEND][IDX["AY"]]) == end_point(C))
    check("n is prime (independent test)", is_prime(n0))
    check("chain links: every q is the next n", all(chain[i]["q"] == chain[i + 1]["n"] for i in range(4)) and chain[-1]["q"] == 3)

    print("\n2) every load-bearing cell matters: mutate one cell, expect a violation")
    used = {
        "ec": {"AX", "AY", "L1", "TX", "TY", "L2", "I2", "WX", "WY", "VX", "VY", "L3", "I3", "XX", "XY", "BN", "BS", "EN"},
        "ecend": {"EN"},
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
            for c in range(WIDTH):
                name = COLS[c] if c < BQ0 else ("BQ" if c < BV0 else "BV")
                row = rows[r]
                old = row[c]
                row[c] = (old + 1) % P
                hit = False
                for rr in range(max(0, r - 1), min(r + 1, len(rows) - 2) + 1):
                    p = [pub[nm][rr] for nm in PUBN]
                    if any(_constraints(rows[rr], rows[rr + 1], p)):
                        hit = True
                        break
                row[c] = old
                tested += 1
                if name in ("BQ", "BV"):
                    continue
                extra_used = name in used.get(kind, set())
                if kind == "bez" and name == "EA" and desc[r]["which"] == 3:
                    extra_used = True
                if kind == "ferm" and name == "G":
                    extra_used = False
                if extra_used and not hit:
                    undetected_used.append((kind, name, r))
    check(f"every load-bearing cell is tied down ({tested} mutations tried)", undetected_used, [])
    if undetected_used:
        print("    undetected:", undetected_used[:10])
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

    def forged(label, chain_f, scalar_f=None, profile=PROFILE):
        scalar_f = scalar if scalar_f is None else scalar_f
        rows_f = build_rows(chain_f, scalar_f, profile)
        air_f = PrimeAIR(commit(chain_f[0]["n"], scalar_f), profile)
        bad = check_trace(air_f, rows_f)
        print(f"    {label}: violated {sorted(bad)}")
        return bad, rows_f, air_f

    ch = copy.deepcopy(chain)
    q0 = ch[0]["q"]
    while True:
        R0 = rng.randrange(ch[0]["R"] // 2 + 1, ch[0]["R"] + 1)
        if not is_prime(2 * q0 * R0 + 1) and 2 * q0 * R0 + 1 < (1 << 64):
            break
    ch[0] = {"n": 2 * q0 * R0 + 1, "q": q0, "R": R0}
    bad_c, rows_c, air_c = forged("composite n_0", ch)
    check("composite n_0 is rejected (Fermat or Bezout fails)", bool(bad_c))
    ch = make_chain(rng=rng, forced_R={4: 1, 3: 14})
    assert ch[3]["n"] == 197 and is_prime(197) and ch[3]["R"] > 2 * ch[3]["q"] - 1
    bad_r, rows_r, air_r = forged("R = 14 > 2q - 1 with prime n_3 = 197", ch)
    check("R > 2q - 1 (prime n, valid Fermat and Bezout) is rejected, caught by the range-bit recomposition",
          sorted(bad_r), ["recomp_V"])
    ch = make_chain(rng=rng, terminal=5)
    bad_t, _, _ = forged("terminal q = 5", ch)
    check("a chain that ends at 5 instead of 3 is rejected", "boundary" in bad_t)
    check("trace checked against a commitment with another blinding scalar is rejected",
          "boundary" in check_trace(PrimeAIR(commit(n0, scalar + 1)), rows))
    check("trace checked against a commitment to another n is rejected",
          "boundary" in check_trace(PrimeAIR(commit(n0 + 2, scalar)), rows))
    ch = copy.deepcopy(chain)
    ch[2]["q"] = ch[3]["n"] + 2 * ch[3]["n"]
    ch[2]["n"] = 2 * ch[2]["q"] * ch[2]["R"] + 1
    bad_l, _, _ = forged("tier 2 uses a q that is not the next tier's n", ch)
    check("broken tier link is rejected", "tier_link_n_is_q" in bad_l or bool(bad_l))
    qc = next(x for x in range(200, 512) if not is_prime(x) and x % 2 == 1)
    ch = make_chain(rng=rng, forced_q={2: qc})
    bad_k, _, _ = forged(f"tier 2 built on the composite q' = {qc} (a skipped factorisation)", ch)
    check("a skipped factorisation is caught by the tier link alone", sorted(bad_k), ["tier_link_n_is_q"])
    rows_b = copy.deepcopy(rows)
    r_g = by_kind["rngG"][0]
    rows_b[r_g][IDX["G"]] = (rows_b[r_g][IDX["G"]] + (1 << 70)) % P
    rows_b[r_g][IDX["V"]] = rows_b[r_g][IDX["G"]]
    check("a base above 2^64 is rejected by the range check", bool(check_trace(air, rows_b)))

    print("\n3b) one forged trace per constraint, each violating exactly that constraint")
    cheats = _single_family_cheats(rng)
    names = sorted(set(air0.names))
    for nm in names:
        check(f"{nm}: the forged trace violates exactly this constraint", cheats.get(nm), {nm})
    check("every constraint of the AIR has such a forged trace", sorted(cheats), names)

    print("\n3c) the factor-q condition: the circuit checks y_q^(2q) = 1, which is enough (see the module docstring)")
    def lemma_counterexample(q_max=41, need_gcd=True, r_max=lambda q: 2 * q - 1):
        import math as _m
        for q in range(3, q_max + 1, 2):
            if not is_prime(q):
                continue
            for R in range(1, r_max(q) + 1):
                n = 2 * q * R + 1
                if is_prime(n):
                    continue
                for a in range(n):
                    yq = pow(a, 2 * R, n)
                    if (not need_gcd or _m.gcd(yq - 1, n) == 1) and pow(yq, 2 * q, n) == 1:
                        return (q, R, n, a)
        return None
    check("no composite n = 2qR + 1 (odd prime q <= 41, 1 <= R <= 2q - 1) has a base with gcd(yq - 1, n) = 1 and yq^(2q) = 1",
          lemma_counterexample() is None)
    print("    the same search finds counterexamples when a hypothesis is dropped (so the search can fail):")
    check("... without the gcd(yq - 1, n) = 1 condition", lemma_counterexample(need_gcd=False) is not None)
    check("... with R allowed up to 4q (the bound 4q^2 > n is needed)", lemma_counterexample(r_max=lambda q: 4 * q) is not None)

    print("\n3d) forged witnesses are rejected by the STARK verifier itself, not only by the local constraint checker")
    for name in ("exp_is_q", "x_bezout_yq", "x_ferm_q_value", "range_slack_q", "tier_link_n_is_q"):
        rows_f, C_f = _FORGED[name]
        air_f = PrimeAIR(C_f, PROFILE)
        locally = bool(check_trace(air_f, rows_f))
        proof_f = S.prove(air_f, rows_f, _force=True)
        check(f"{name}: the forged trace violates a constraint and the verifier rejects its forced proof",
              (locally, verify_prime(C_f, proof_f)), (True, False))

    print("\n4) end to end: prove and verify")
    t0 = time.time()
    C_, proof = prove_prime(chain, scalar)
    t_prove = time.time() - t0
    t0 = time.time()
    ok = verify_prime(C_, proof)
    t_ver = time.time() - t0
    check("honest proof accepted", ok)
    print(f"    prove {t_prove:.1f} s, verify {t_ver:.2f} s, proof {S.proof_size_bytes(proof) / 1024:.0f} KiB")
    check("commitment is n*G + s*H", C_ == commit(n0, scalar))
    check("proof checked against another commitment: rejected", verify_prime(SC.add(C_, SC.G), proof), False)
    check("proof checked against a commitment to another n (same blinding): rejected", verify_prime(commit(n0 + 2, scalar), proof), False)
    check("a commitment point off the curve is rejected", verify_prime((C_[0], (C_[1] + 1) % P), proof), False)
    check("proof checked against another profile: rejected", verify_prime(C_, proof, profile=(64, 33, 17, 9, 6)), False)
    check("the honest prover refuses a forged chain (composite n_0)", _refuses(lambda: S.prove(air_c, rows_c)))
    check("a forced proof of the composite n_0 is rejected", verify_prime(air_c.C, S.prove(air_c, rows_c, _force=True)), False)
    check("a forced proof with R > 2q - 1 is rejected", verify_prime(air_r.C, S.prove(air_r, rows_r, _force=True)), False)
    blob = repr(proof).encode()
    check("n and the blinding scalar do not appear in the proof", str(n0).encode() not in blob and str(scalar).encode() not in blob)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy STARK; soundness conjectured, zero knowledge argued; unaudited.")
    return 1 if failures else 0


_FORGED = {}                                       # name -> (rows, public commitment), filled by _single_family_cheats


def _single_family_cheats(rng):
    """One forged trace per constraint, each violating EXACTLY that constraint (all others hold). Returns
    {name: set of violated constraint names}. If a constraint is removed from the AIR, the cheat built for it
    becomes a valid-looking trace, so the assertion in the self-test fails: this is the removal check, made
    permanent. The cheats are real attacks (wrong exponent, forged commitment, non-boolean bit, a G-scalar that
    wraps modulo the field, ...)."""
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
    scalar = secrets.randbits(EC_BITS)
    out = {}

    def run(name, cheat=None, edit=None, chain_c=None, record=True):
        rows = build_rows(chain_c or chain, scalar, PROFILE, cheat)
        if edit:
            edit(rows)
        _FORGED[name] = (rows, commit((chain_c or chain)[0]["n"], scalar))
        air = PrimeAIR(None)
        # the forged trace brings its own final point: the public statement is whatever it computed
        air.boundary = [(IDX["AX"], ECEND, rows[ECEND][IDX["AX"]]), (IDX["AY"], ECEND, rows[ECEND][IDX["AY"]]),
                        (IDX["QR"], air.first_rows[-1], 3)]
        if record:
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
    # attacks on the factor-q condition, kept for the verifier-level test (they share a constraint family with the factor-2 cheats)
    run("x_bezout_yq", edit=bump("bez", "Q", 1, which=3), record=False)
    run("x_ferm_q_value", edit=bump("ferm", "V", 1, chk="q"), record=False)
    run("bez_to_ladder3_G", {"tier": 3, "shift3": 1})
    run("mul_to_bez_A", {"tier": 3, "shift3": 2})
    run("m_is_qR", {"tier": 3, "R_mult": 3})
    run("n_is_2m_plus_1", {"tier": 3, "R_mult": 3, "mm_follows": True})
    # two non-boolean bits (1 + n and -2n) that cancel in the exponent register: an affine step x' = u + EB (mm - u)
    big = make_chain(rng=rng)
    run("bit_boolean", {"tier": 2, "ebj": {1: {1: 1, 2: -2}}}, chain_c=big)

    # ---- the in-circuit commitment C = n*G + s*H (the forged trace computes its own point; the builder keeps every
    # gadget consistent except the one named)
    n0 = chain[0]["n"]
    n_alt = n0 - 2                                             # any other integer below 2^64
    r0, rg = 100, 200                                          # a row without G (r < 188) and one with G
    for name, row, cell in (("ec_dbl_lam", r0, "L1"), ("ec_dbl_x", r0, "TX"), ("ec_dbl_y", r0, "TY"),
                            ("ec_G_lam", rg, "L2"), ("ec_G_inv", rg, "I2"), ("ec_G_x", rg, "WX"),
                            ("ec_G_y", rg, "WY"), ("ec_G_selx", rg, "VX"), ("ec_G_sely", rg, "VY"),
                            ("ec_H_lam", rg, "L3"), ("ec_H_inv", rg, "I3"), ("ec_H_x", rg, "XX"),
                            ("ec_H_y", rg, "XY"), ("ec_H_selx", rg, "AX_next"), ("ec_H_sely", rg, "AY_next")):
        run(name, {"ec": {"tamper": {(row, cell): 1}}})
    run("ec_bnG_zero", {"ec": {"n_val": n0 + P}})              # n0 + p is congruent to n0 in the field but commits another value
    b200, b201 = (n0 >> (EC_BITS - 1 - 200)) & 1, (n0 >> (EC_BITS - 1 - 201)) & 1
    run("ec_bn_bool", {"ec": {"bn_vals": {200: b200 + 1, 201: b201 - 2}}})   # +2^51 and -2*2^50 cancel in the register
    run("ec_bs_bool", {"ec": {"bs_vals": {r0: ((scalar >> (EC_BITS - 1 - r0)) & 1) + 2}}})
    run("ec_En", {"ec": {"n_val": n_alt, "en_jump": (r0, (n0 - n_alt) * inv2(EC_BITS - 1 - r0) % P)}})
    run("ec_start_En", {"ec": {"n_val": n_alt, "en0": (n0 - n_alt) * inv2(EC_BITS) % P}})
    run("ec_start_ax", {"ec": {"start": (SC.D[0] + 1, SC.D[1])}})
    run("ec_start_ay", {"ec": {"start": (SC.D[0], SC.D[1] + 1)}})
    run("ec_link_n", {"ec": {"n_val": n_alt}})                  # commits n_alt, proves n0 prime

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
