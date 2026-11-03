# PrimeCollapse Protocol Specification (draft 1.0)

Status: educational prototype, unaudited. This document describes what `goldbach_stark.py` and the modules it uses
do, so that a second verifier can be written without reading the Python. Where the code and this document disagree,
the code is what runs; please report the difference. Nothing here is a security proof. The statements marked
**Proven** are arithmetic facts that a reader can check; **Assumed** and **Argued** mark what is not.

## 0. Statement

Public: an integer `c`, with `0 <= c < 2^65`. The prover knows primes `a <= b < 2^64` with `a + b = 2c` and
`a <= c <= b`. The verifier learns `c` (hence `a + b`) and the chain-length profile `(64, 33, 17, 9, 5)`; the
goal is that it learns nothing else about `a`, `b`, the Pocklington chains or any blinding value.

Not claimed: that the Goldbach conjecture is proved (the name is historical), that any number larger than 2^64 can be
handled, post-quantum security, or any property of a production system.

Conventions: integers are written in decimal inside hashed strings; `||` is byte concatenation; `H256` is SHA-256;
`int(x)` reads a 32-byte digest as a big-endian integer.

## 1. Parameters

### 1.1 Repository group (zkrp_toy.py)

`P = 2Q + 1`, 256-bit safe prime (`Q` has 255 bits), fixed constants with a deterministic primality certificate
(`group_params.py`):

```
P = 0xb8f344dc29e7ea92c63af4fa56718631ea89925a13bcd4bee8880462fddd2903
Q = 0x5c79a26e14f3f549631d7a7d2b38c318f544c92d09de6a5f744402317eee9481
```

Pocklington's theorem (used for every step): if `n - 1 = 2qR` with `q` prime, `1 <= R <= 2q - 1` (so `(2q)^2 > n`), and a base `a`
satisfies `a^(n-1) = 1`, `gcd(a^((n-1)/2) - 1, n) = 1` and `gcd(a^((n-1)/q) - 1, n) = 1`, then `n` is prime.

Derivation (`group_params.derive`, seed `b"zkrp-toy-group-v2"`), all deterministic:
1. Tier 0: `q0 = 65537`, prime by trial division.
2. Tiers 1 to 3: with `q` the previous prime, for `ctr = 0, 1, ...` take `R = q + (X mod q)` with
   `X = int(H256(seed || tier || ctr || 0x00) || H256(seed || tier || ctr || 0x01))` (`tier` one byte, `ctr` eight bytes big-endian),
   `n = 2qR + 1`; the first `n` with a Pocklington witness (smallest `a >= 2`) is the next prime.
3. Tier 4: `R` is drawn the same way in the range that makes `Q = 2qR + 1` exactly 255 bits; accept the first `Q` that has a witness
   and whose `P = 2Q + 1` has a witness for the known factor `Q` (`a^(P-1) = 1`, `gcd(a^2 - 1, P) = 1`, `Q^2 > P`).
   Trial division by odd primes below 1000 and a base-2 Fermat test only skip candidates; acceptance is the witness test.

The certificate is `[(R, a)]` for the four tiers plus the witness for `P`:
`[(67969, 2), (16538368284, 5), (494959946627345494860, 7), (71694156909245637217911358225110080, 3)]` and `a_P = 2`. `verify_certificate(P, Q, cert)` recomputes every
step, and `python group_params.py` re-derives the constants from the seed and compares. A reader can check
primality of `P` and `Q` with a handful of modular exponentiations; no probabilistic test is involved. The subgroup of order
`Q` is the set of quadratic residues; `_element(x)` accepts exactly integers `0 < x < P` with Jacobi symbol 1.

Generators (`hash_to_subgroup(label)`): for `ctr = 0, 1, ...`, `digest = H256(label || ctr as 4-byte BE || 0 as 2-byte BE) ||
H256(label || ctr as 4-byte BE || 1 as 2-byte BE)` (512 bits), `x = (int(digest) mod P)^2 mod P`; the first `x` not in
`{0, 1}` is the result. Labels: `b"zkrp-toy-g"` gives `g`, `b"zkrp-toy-h"` gives `h`:

```
g = 0x3bc7d5e6f97593d3ac856fc77e707168bbf9231305dfee5082797c8ea8ae77e7
h = 0x613af5394bcbfbe5559cd7d0b5481741db29d0cfefaa09f70ac73fcb1c052121
```

Commitment: `Com(m, r) = g^(m mod Q) * h^(r mod Q) mod P`.

### 1.2 Stark curve (stark_curve.py)

Field `F_p`, `p = 2^251 + 17 * 2^192 + 1`. Curve `y^2 = x^3 + x + beta`, `beta` as in `stark_curve.py`, group order `Q_C`
(prime, about `2^251`), generator `G`. These constants appear to be the published Stark curve; a reviewer should compare
them with StarkWare's own specification. An external reviewer reported a match with independent implementations of the published
Stark curve (field prime, `alpha = 1`, `beta`, order, generator); the canonical StarkWare source is still to be cited here.

`H` and `D` come from `hash_to_point(label)`: for `ctr = 0, 1, ...`, `x = int(H256(b"stark_curve|" || label || b"|" ||
ASCII decimal of ctr)) mod p`; if `x^3 + x + beta` has a square root, return `(x, y)` with `y` the even root (Tonelli-Shanks
root, replaced by `p - y` when odd). Labels `b"H"` and `b"D"`.

```
H = (0x7fc67f23180fafc9d290f99dbe1cd65b9e649bd760e31b2457cd56864bb698c, 0x67c813a56adf9e2b613b501d8bca4e6e54cb81bb05b3e6a52565b350ceb81b8)
D = (0x3c2c531d028c143430a1ce8b851da78397c958798bd614ee28023a0f9acbade, 0x6698a75b0f09e90c033d42f9c9dab2490671af431be2f416708cd57de6450de)
```

Commitment: `ComC(n, s) = n*G + s*H`, scalars reduced modulo `Q_C`. `Q_C * G = infinity` is checked with an unreduced scalar multiplication
(`mul_unreduced`; the ordinary `mul` reduces its scalar, so `mul(Q_C, G)` would be the identity whatever `Q_C` is). `D` is used only inside the circuit (section 4.2).

### 1.3 Primality assurance of the parameters

| Parameter | Assurance | Status |
| --- | --- | --- |
| `P`, `Q` (repository group) | Pocklington chain `65537 -> n1 -> n2 -> n3 -> Q`, then `P = 2Q + 1` by a witness for the factor `Q` (`Q^2 > P`); certificate in `group_params.py`, verified on every import | **Proven** (deterministic), assuming nothing beyond arithmetic |
| `p` (Stark field) | `p - 1 = 2^192 * 5 * 7 * 98714381 * 166848103`; each factor is prime (deterministic Miller-Rabin below 3.3e24); Pocklington witnesses checked in `stark_curve.py` | **Proven** (deterministic) |
| `Q_C` (curve order) | `Q_C - 1 = 2 * 3 * 1481071 * 74436419 * R` with `R = 5470365079085120887157193270902448565659295524958143968059153` (202 bits); `R - 1 = 2^4 * 3 * 131797 * 10108547 * 22206313 * 74837449 * 28547348873 * 1803099112058626586861`; every prime factor below 3.3e24 is proven by deterministic Miller-Rabin; Pocklington witnesses for `R` and for `Q_C` (`stark_curve.certify_prime`) | **Proven** (deterministic) |

Note: `Q` prime does not by itself make `P = 2Q + 1` prime. What does is the Pocklington witness for the factor `Q` with
`Q^2 > P`; the certificate includes it, and the derivation only accepts a `Q` whose `P` passes it.

The certificates for `p` and `Q_C` are checked by `python stark_curve.py`, which also holds crafted counterexamples for every condition of the certificate check.
The factorisations were found by trial division and Pollard rho; the check does not rely on how they were found.

Assumed: the hash outputs behave like random oracles, so nobody knows `log_g h` (repository group) or `log_G H`
(curve). The tests can show only subgroup membership and distinctness.

## 2. Midpoint and range proof (zkrp_toy.py)

Range width `N = 64` bits for the combined proof (`Z.set_range_bits(64)`; the requirement `2^(N+3) < Q` holds).

Prover, given `a <= b`, `a + b` even, `c = (a + b)/2`, `x = c - a`:
1. `ra, rb` uniform in `[0, Q)`. `Ca = Com(a, ra)`, `Cb = Com(b, rb)`.
2. `tag = hex(H256(f"{N}|{c}|{Ca}|{Cb}"))[:32]`.
3. Range proof for `Ca` with context `"a:" + tag` (value `a`, blinding `ra`), and for `Cx = g^c / Ca` with context `"x:" + tag`
   (value `x`, blinding `-ra mod Q`).
4. Sum proof: `s = ra + rb`, `Dm = Ca * Cb * g^(-2c)` (equals `h^s` iff `a + b = 2c` modulo `Q`); `t` uniform in `[0, Q)`,
   `T = h^t`, `e = Ch(c, Ca, Cb, T)`, `z = t + e*s mod Q`.

`Ch(items) = int(H256(b"|".join(str(i).encode() for i in (P, g, h) + items))) mod Q`.

Range proof of `C` for width `N` (context `ctx`): bit commitments `B_i = Com(bit_i, r_i)`, `i = 0..N-1`, with
`sum r_i 2^i = r (mod Q)`, so `prod B_i^(2^i) = C`. Each `B_i` carries a Schnorr OR proof (`B_i = h^r` or `B_i / g = h^r`) of
six values `(T0, T1, e0, e1, z0, z1)` with `e0 + e1 = Ch(f"{ctx}:{i}", B_i, T0, T1) mod Q` and
`h^zj = Tj * Yj^ej` where `Y0 = B_i`, `Y1 = B_i * g^-1`.

Verifier accepts iff all hold: `c` is an `int` with `0 <= c < 2^(N+1)`; `Ca`, `Cb`, `T` are subgroup elements and `z` is a
canonical scalar in `[0, Q)`; the sum equation `h^z = T * Dm^e` holds with `e = Ch(c, Ca, Cb, T)`; both range proofs verify
(all group elements in the subgroup, all scalars canonical, recombination equals `Ca` resp. `Cx`).

Integer guarantee (**Argued from the checks**): range proofs bind `a, x` to `[0, 2^N)` as integers (below `Q`), and the sum proof binds
`a + b = 2c` modulo `Q` with `c < 2^(N+1)`; because `2^(N+3) < Q` nothing wraps, so `a + b = 2c` and `a <= c <= b` hold over
the integers (`b = a + 2x`). The soundness of the bit proofs and the sum proof rests on the discrete-logarithm assumption
in the group and the random-oracle model; no proof is given here.

## 3. Primality STARK (stark_core.py, stark_primality.py)

### 3.1 Field and parameters

`p` as in section 1.2; the STARK field is `F_p`. `GEN = 3^C` with `C = 2^59 + 17` is a generator of the 2^192-order
two-adic subgroup; evaluation domain coset shift `3`; field elements are 32 bytes, big-endian. `BLOWUP = 8`, `QUERIES = 40`,
`FINAL_DEG = 8`, random padding rows `2*QUERIES + 2 = 82`; trace length `N` is the next power of two above `real_rows + 82`.

### 3.2 Hashing

`Transcript(label)`: state `h = H256(b"stark_core|" + label)`; `absorb(d)`: `h = H256(h || d)`; `field()`: `h = H256(h || b"f")`,
output `int(H256(h||"1") || H256(h||"2") || H256(h||"3")) mod p`; `index(n)`: `h = H256(h || b"i")`, output `int(h) mod n`.
Merkle tree over `H256(0x00 || data)` leaves and `H256(0x01 || left || right)` inner nodes. The statement hash binds
width, rows, degree, constraint count, boundary conditions, `N`, the three FRI parameters, the public columns and
`b"stark_primality|v2|" + repr((profile, G, H, D))`.

### 3.3 What the circuit enforces

Columns (29 named, 157 including bit columns), 183 constraints, degree 3. A trace has three kinds of rows:
- 252 `ec` rows plus one `ecend` row: double-and-add of the commitment. The accumulator starts at `D`; each row doubles it;
  it adds `G` when the witness bit `BN` is set (only in the last 64 rows, so `n < 2^64` and cannot wrap), and `H` when the
  blinding bit `BS` is set; every addition proves its two x-coordinates differ by supplying an inverse. The register `EN`
  collects the bits of `n`. Boundary: the accumulator at the `ecend` row equals `C + 2^252 * D`, where `C` is the public
  commitment, and `EN` equals the chain's top `n` on the link row.
- five Pocklington-style tiers, sizes `(64, 33, 17, 9, 5)` bits. Per tier: `n = 2qR + 1` with `1 <= R <= 2q - 1`. Factor 2:
  `y2 = a2^((n-1)/2)` with `y2^2 = 1` and `gcd(y2 - 1, n) = 1` (so `a2^(n-1) = 1`, the usual condition). Factor `q`:
  `yq = aq^((n-1)/q)` with `gcd(yq - 1, n) = 1` and `y3^2 = 1` where `y3 = yq^q`, that is `yq^(2q) = 1`, which is WEAKER than the
  usual `aq^(n-1) = 1` (`y3 = 1`). The weaker form is still sufficient, by an argument that is not Pocklington's theorem as
  stated: for an odd prime `q`, `n = 2qR + 1`, `1 <= R <= 2q - 1`, every prime `p | n` has `ord_p(yq) in {2, q, 2q}`; order
  `q` or `2q` forces `q | p - 1` (so `p >= 2q + 1`), order 2 forces `yq = -1 (mod p)` and `2^(v2(R)+2) | p - 1`; if all prime
  divisors were of the second kind, `n = 1 (mod 2^(v2(R)+2))` would contradict `v2(n-1) = v2(R) + 1`; the product `M` of
  the second-kind prime powers satisfies `M = 1 (mod q)`, `M` odd and `M < 2q`, so `M = 1`; then every prime divisor is `>= 2q + 1`
  and a composite `n` would exceed `4q^2`. The full argument is in the docstring of `stark_primality.py`; the self-test
  confirms it exhaustively for all odd primes `q <= 41` (every `R`, every base) and shows the search finds counterexamples if
  the gcd condition or the bound `R <= 2q - 1` is dropped. This argument needs independent review. The gcd conditions use
  inverse witnesses; modular multiplication `A*B = Q*N + V` with 64-bit range-checked quotient and remainder; exponents are
  square-and-multiply ladders with witness bits and an exponent register compared with `(n-1)/2`, `2R` or `q`.
- tier links (each `q` is the next tier's `n`) and the terminal value `q = 3`.

Public input: the curve point `C`. Proof: a hash-based STARK with DEEP composition and FRI over the Merkle trees above.
Soundness: **Assumed** (the usual conjectured FRI proximity bound; roughly 3 bits per query at rate 1/8, so an estimate of
about 120 bits for 40 queries, which is not proven and was not reviewed). Zero knowledge: **Argued** (82 random padding rows
exceed the number of queried positions, plus a random mask); not proven.

Removal checks: for each constraint family a forged trace violates exactly that family (57 isolated cheats); the
self-test must reject each. The verifier's own checks were removed one at a time as well.

## 4. Cross-group link (link_commitments.py)

Statement: `Ca` (section 1.1) and `C` (section 1.2) hide the same integer `a`, `0 <= a < 2^64`.

Constants: `A_BITS = 64`, `CH_BITS = 128`, `SEC_BITS = 48`, `K_BITS = 240`, `Z_MAX = 2^241`.

Prover, with `Ca = g^a h^ra`, `C = a*G + s*H`:
1. `k` uniform in `[0, 2^240)` (`secrets.randbits(240)`), `u1` uniform in `[0, Q)`, `u2` uniform in `[0, Q_C)`.
2. `T1 = g^k h^u1 mod P`, `T2 = k*G + u2*H`.
3. `e = int(H256(f"link_commitments|v1|{P}|{g}|{h}|{G}|{H}|{Ca}|{C}|{T1}|{T2}")) >> 128`, so `e` is the top 128 bits (point
   tuples are printed as Python tuples).
4. `z = k + e*a` (an integer, no reduction), `w1 = u1 + e*ra mod Q`, `w2 = u2 + e*s mod Q_C`.

Verifier accepts iff `Ca` is a subgroup element, `C` is a finite curve point, the proof has exactly the keys `T1, T2, z, w1, w2`,
`T1` is a subgroup element, `T2` a curve point, `z` is an `int` with `0 <= z < 2^241`, `w1` in `[0, Q)`, `w2` in `[0, Q_C)`, and
`g^z h^w1 = T1 * Ca^e (mod P)` and `z*G + w2*H = T2 + e*C`.

Response bound for every permitted input: `z = k + e*a <= (2^240 - 1) + (2^128 - 1)(2^64 - 1) < 2^240 + 2^192 < 2^241`.

Extraction (**Argued**, interactive special soundness; the Fiat-Shamir transformation is a separate argument, see the last paragraph of this section): take two accepting transcripts with equal `(T1, T2)` and challenges `e != e'`, and let
`D = z - z'` and `Delta = e - e'`, so `0 < |Delta| < 2^128` and `|D| < 2^241`. Dividing the first equation by itself gives
`Ca^Delta = g^D h^(w1-w1')`, hence `Ca = g^(D/Delta) h^((w1-w1')/Delta)` with exponents taken modulo `Q` (`Delta` is invertible
because `|Delta| < 2^128 < Q`). The second equation gives, in the same way, `C = (D/Delta mod Q_C) G + (...) H`. Under the
discrete-logarithm assumption for `(g, h)` and for `(G, H)`, binding fixes the opening, so the committed value in the
repository group is `a_Z = D/Delta mod Q` and in the curve group `a_C = D/Delta mod Q_C`. The range proof gives
`0 <= a_Z < 2^64` and the STARK gives `0 <= a_C < 2^64`, so `Delta*a_Z` and `Delta*a_C` are integers of absolute value
below `2^192`. Then `Delta*a_Z - D` and `Delta*a_C - D` have absolute value below `2^242`, which is smaller than both
`Q` (about `2^255`) and `Q_C` (about `2^251`); each is divisible by the respective order and so is zero. Therefore
`Delta*a_Z = D = Delta*a_C` over the integers and `a_Z = a_C`. The bound `z < 2^241` is what makes this valid: without it a
response congruent modulo `Q*Q_C` would extract unequal integers (the self-test builds `a + Q_C` and checks the rejection).

Losses not accounted for: the argument above is for the interactive protocol with rewinding; the Fiat-Shamir version needs
the forking lemma and the random-oracle model, which costs a concrete security factor that is not computed here.

Hiding (**Argued**): `z = k + e*a` with `k` uniform on `[0, 2^240)` is within statistical distance `e*a / 2^240 < 2^-48`
of a value independent of `a`. `w1`, `w2` are uniform because `u1`, `u2` are uniform. Honest-verifier zero knowledge by
the usual simulation; the Fiat-Shamir transcript additionally needs the random-oracle model.

## 5. Composition (goldbach_stark.py)

Prover: sort so `a <= b`; run section 2 at 64 bits to get `(c, Ca, Cb, ...)` and the blindings; for each endpoint choose
`s` uniform in 252 bits (the code uses `secrets.randbits(252)`), run section 3 for the certified chain of that endpoint to obtain `(C, stark)`
and section 4 on `(a_i, r_i, s)` to obtain the link; output `{"mid", "a": {"C", "link", "stark"}, "b": {...}}`.

Verifier accepts iff: the dictionary has exactly the keys `mid, a, b`; each part has exactly `C, link, stark`;
section 2 verifies; for `a` and `b`: section 4 verifies against `mid.Ca` / `mid.Cb` and the part's `C`, and section 3 verifies
for the part's `C`. The function returns `False` for any malformed input.

Tied by composition: the link makes `C_a` hide the same integer as `Ca`; the STARK makes that integer prime; the range
proofs and sum proof tie `Ca`, `Cb` to `c`. A stolen STARK for another number is rejected by the link, and swapping the parts
is rejected by the binding to `Ca` and `Cb` (checked in the self-test).

## 6. Assumptions and known limitations

1. Discrete log is hard in the repository group and on the Stark curve, and `log_g h`, `log_G H` are unknown (random-oracle
   assumption on the hashes; not provable).
2. SHA-256 behaves as a random oracle in all Fiat-Shamir transcripts and in the STARK.
3. FRI soundness is the conjectured bound (not proven). Zero knowledge of the STARK is argued with random padding and a mask.
4. The primality of `P`, `Q`, `p` and `Q_C` is proven by deterministic certificates (section 1.3). That a parameter is prime says nothing
   about the strength of the curve beyond its published design.
5. Range only to 64 bits; the Pocklington profile is fixed at five tiers, so the chain length is public.
6. Home-made constructions: the in-circuit commitment, the AIR, the link proof and the composition. No independent review.
7. Not constant-time; pure Python; proofs are about 1.1 MB and take about 22 s to produce.
8. The serialization in the code uses Python `repr`/`str` for hashed values, so a second implementation must reproduce those
   exact strings (section 1, section 4 and `stark_primality.extra`).
9. This document is a first draft written from the code; items marked Argued need a reviewer's attention.
