# Audit of SPEC.md section 3.4 against the cited theorems (revision 2)

Status: **unreviewed working audit. This is not a security claim.** The project does not prove the Goldbach conjecture and the
STARK is a toy, unaudited prototype. `QUERIES = 40`, `BLOWUP = 8` stay **experimental**; no code and no parameter was changed.

Revision 2 replaces revision 1 after reading the two papers in full text (see section 0). Statements marked **[derived]** are my own
arguments assembled from those theorems; they have not been reviewed by anyone and are the main thing to check.

## 0. Sources actually read

| Source | Version | Read |
| --- | --- | --- |
| BCIKS: Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for Reed-Solomon Codes* | ECCC TR20-083, dated May 30, 2020 (47 pp.) | Theorems 1.2, 1.4, 1.6, 1.7; Section 7.2 (Theorem 7.2 "FRI Soundness", Conjecture 7.3) in full text. **In this version the FRI theorem is Theorem 7.2, not 8.3; earlier references to "Theorem 8.3/Conjecture 8.4" were wrong numbering.** Proofs not checked. |
| Garreta, Mohnblatt, Wagner, *A Simplified Round-by-round Soundness Proof of FRI* | dated August 25, 2026, "full version of a paper appearing at IACR TCC 2026" (31 pp.) | Definitions 2.2, 2.3, 3.4, 3.5; Lemma 2.4 (quoted from [BCH+25]); Theorem 5.2; Corollary 5.6; Appendix A (batched FRI) statements. Proofs not checked. |
| DEEP-FRI (BGKS), arXiv 1903.12243 v1 | v1 | Theorem 4.1, Lemma 5.3, Protocol 5.4, Theorem 5.5 (earlier session); Section 6 truncated. |
| BCS16 | eprint 2016/116 | Theorems 1-3 reconstructed from a garbled PDF. |
| Haboeck 2022/1216, ethSTARK documentation, BBHR18, Fenzi 2025/2197, [BCH+25] | - | **not read** |

## 1. Statements used (quoted or closely paraphrased)

**BCIKS Theorem 1.2** (proximity gap for affine spaces) and **Theorem 1.7** (correlated agreement over affine spaces). `RS[F_q, D, k]` has
dimension `k+1`, blocklength `n = |D|`, rate `rho = (k+1)/n`. For `u_0, ..., u_l` in `F_q^D` and `U = u_0 + span{u_1..u_l}`: if
`delta in (0, 1 - sqrt(rho))` and `Pr_{u in U}[Delta(u, V) <= delta] > eps`, then there exist `D' subset D` with `|D'|/|D| >= 1 - delta`
and `v_0..v_l in V` with `v_i = u_i` on all of `D'` (one common `D'` for all `i`). Error: `eps_U = n/q` for `delta <= (1 - rho)/2`;
`eps_J = (k+1)^2 / (2 min(eta, sqrt(rho)/20))^7 / q` for `delta in ((1-rho)/2, 1 - sqrt(rho))`, `eta = 1 - sqrt(rho) - delta`.
The error does **not** depend on the number `l` of functions for affine spaces (independent coefficients). **Theorem 1.6** (curves, i.e.
powers of one challenge) loses a factor `l`.

**BCIKS Theorem 7.2** (FRI soundness). `D^(0)` coset of a 2-smooth group, `rho = (k^(0)+1)/n^(0) = 2^-R`; `f^(0)` is at least `delta`-far from
the code, `delta <= 1 - sqrt(rho) - eta`, `0 < eta <= sqrt(rho)/20`. COMMIT error
`eps_C <= rho^2/((2 eta)^7 |F|) * sum_j (l^(j) - 1) n^(j+1) < (k^(0)+1)^2 / ((2 eta)^7 |F|)`; with probability `>= 1 - eps_C` over the
folding challenges a single QUERY iteration accepts with probability `<= 1 - delta`; total `eps_FRI <= eps_C + (1 - delta)^t`.
It is stated for the interactive protocol with `f^(0)` an oracle, `k^(i)+1` a power of two, and `q >> n^2` (quadratic field).

**Garreta et al. Theorem 5.2** (round-by-round soundness of FRI, Construction 4.4: `d_0 <= |L_0|/2`, folding factors `m_i`, `t` repetitions,
final function `f_k` read in full and checked to be in `C_k`). Assuming the Powers generator has mutual correlated agreement with error
`eps_mca` (Lemma 2.4, from [BCH+25]), for every `theta in [0,1]`: `eps_i^fold = eps_mca(C_i, m_i, theta)` for each folding round and
`eps^qry(delta) = (1 - min{theta, delta})^t`, where `delta = Delta(f_0, C_0)`. Lemma 2.4: for `gamma < 1 - sqrt(rho)`,
`eps_mca(C, m, gamma) = (m-1)/|F| * ( (2(eta+1/2)^5 + 3(eta+1/2) gamma rho)/(3 rho^(3/2)) * |L| + (eta+1/2)/sqrt(rho) )`,
`eta = max(ceil(sqrt(rho)/(1 - sqrt(rho) - gamma)), 3)`. **Informal Fiat-Shamir remark (Section 3.2):** a prover making `Q_i` oracle queries in round `i`
succeeds with probability at most `Q_1 eps_1 + ... + Q_k eps_k <= (Q_1+...+Q_k) max_i eps_i`, so "the security level is about `floor(-log max_i eps_i)`".
The formal RBR-to-Fiat-Shamir theorem is cited to [BCS16, CCH+19, Hol19] and **not read**.
Note: the paper says mutual correlated agreement (MCA) was a conjecture when first published and, per the paper, is now known "in the same regimes as correlated
agreement" via [Zei24, BCH+25, BCGM25, Hab25]; I did not read those.

**Garreta et al. Appendix A** (batched FRI, Theorem A.2): batching of `b` functions by powers of a challenge, with its own `eps`; not the
independent-coefficient DEEP combination used here.

## 2. Parameter mapping (implementation vs theorems)

| Implementation | Value | Theorem notation | Match |
| --- | --- | --- | --- |
| field | `p = 2^251 + 17*2^192 + 1` (`log2 p = 251.0`) | `q`, `|F|` | SPEC wrote `~2^252`, `2^-240`; corrected to `2^251`, `2^-239` |
| FRI domain | coset `3<w>`, `n0 = 8192` | `L_0`, `n` | coset of a 2-power group: matches Thm 7.2 and Construction 4.4; closed under `x -> -x` |
| FRI code | RS with `k^(0)+1 = N = 1024`, `rho = 1/8 = 2^-3` | `RS[F, D^(0), k^(0)]`, `rho = 2^-R`, `R = 3` | matches; `k^(i)+1`: 1024, 512, ..., 8 are powers of two |
| honest `F` | degree `<= N - 2` (`< N - 1`) | in `RS(k+1 = N)` | slack of one degree: the code FRI tests (deg `< N`) is strictly larger than the honest degree; the proof must use the larger code (section 5) |
| folding | arity 2, 7 rounds, layers 1-6 committed, layer 7 = final polynomial (`< 8` coefficients) sent in clear | `m_i = 2`, `k = 7`, `f_k` read in full | matches Construction 4.4 (final function check is automatic for a polynomial of degree `< 8`; the verifier must still check it against the opened layer-6 values, which it does) |
| queries | `t = 40`, `j0` uniform in `[0, n0/2)`, opens `j0` and `j0 + n0/2` | `s_j <- L_0`, `Block(s_j)` | uniform block = uniform point of `L_0` up to the pairing; with replacement, like the theorems |
| challenge for DEEP | 317 independent field elements `gamma_c, gamma2_c, delta_i` | Thm 1.7 affine space `u_0 + span{u_1..u_l}` | matches Thm 1.7 (not Thm 1.6/Powers); `l`-independent error (section 5) |
| initial oracle | `F` computed by the verifier from Merkle openings of `T_c`, `cp_i` | `f_0` an oracle | standard "virtual oracle"; each queried value of `F` costs openings of both trees |

Batching count (resolves the earlier 160/163/317 confusion): 160 committed oracles (157 trace columns, 3 pieces); **317** terms in `F`
(157 at `z`, 157 at `gz`, 3 pieces at `z`), each with its own coefficient; "163" was an arithmetic error. By Thm 1.7 the number of terms `l` does not enter the error for independent coefficients.

## 3. Instantiated constants (all with `|F| = p`, `n0 = 8192`, `rho = 1/8`, `sqrt(rho) = 0.3536`)

- BCIKS Thm 1.7 unique decoding: `eps_U = n0/p = 2^-238` per application (`+ 1/p` for normalizing the coefficient, see section 5).
- BCIKS Thm 7.2 with `eta = sqrt(rho)/20 = 0.01768`, `delta = 0.6288`: per-query `-log2(1 - delta) = 1.430`, 40 queries: **57.2 bits**; `eps_C = 1024^2/((2 eta)^7 p) = 2^-197`.
  Smaller `eta` trades commit error for a larger `delta`: `eta = 0.010`: 1.460 bits/query, `eps_C = 2^-191.5`; `eta = 0.005`: 1.480, `2^-184.5`. The ceiling of the table is `1.5` bits/query (the SPEC's 60 bits) and is never reached since `eta > 0`.
- Garreta Thm 5.2 with Lemma 2.4 (`m = 2`, `|L| <= 4096`): `eps_fold = 2^-226` at `theta = 0.4375`, `2^-219.6` at `theta = 0.6`, `2^-213.0` at `theta = 0.6288`; query term `(1 - theta)^40`.
- Out-of-domain identity: `(4N + O(1))/(p - N - n0 - 1) ~ 2^-239`.
- Constraint combination: `1/p = 2^-251`.
- Merkle (SHA-256 collisions, `Q_H` hashes): `Q_H^2 / 2^257`.

Every field-dependent term is below `2^-185`; the query term `(1 - delta)^t` and the Fiat-Shamir factor decide the security level.

## 4. Per-query exponent: what is proved for which object

There are two different objects and the SPEC table conflated them.

1. **Plain FRI on an oracle `f_0` that is `delta`-far** (BCIKS Thm 7.2 [read]; Garreta Thm 5.2 [read]): per-query `-log2(1 - delta)` up to `delta = 1 - sqrt(rho) - eta`,
   i.e. **1.43 bits per query (57.2 bits for 40 queries)** at the cap `eta = sqrt(rho)/20`. This is a statement about FRI alone.
2. **The whole construction** (AIR, quotient, one DEEP step, then FRI). To use a large `delta` in FRI one must also show that if `F` is within
   `delta` of the code then the claimed out-of-domain values are consistent. **[derived]** below, this follows from Thm 1.7 only for
   `delta` in the unique decoding regime. For larger `delta` a list-decoding DEEP lemma is required (BGKS Lemma 5.3 or Haboeck; **not available/applied here**).

Hence for the whole construction the exponent supported by what I read is the unique-decoding one: `-log2(1 - 0.4375) = 0.830` bits per query,
**33.2 bits for 40 queries**. The Johnson-radius figure (57.2 bits for 40 queries by Thm 7.2) is available for FRI alone and for the whole protocol
only if a list-decoding DEEP/ALI step is added; it is an open item, not a claim.

## 5. [derived] Composition: one DEEP step then FRI, unique decoding regime

Let `V = RS[F, D, N]` (degree `< N`, `rho = 1/8`, `delta_U = (1 - rho)/2 = 0.4375`), and let `w_1..w_317` be the 317 DEEP quotient words
(`(T_c - tz_c)/(X - z)`, `(T_c - tgz_c)/(X - gz)`, `(cp_i - cz_i)/(X - z)`), all words on `D` fixed before the challenges `gamma` (step 5 precedes step 6;
`z, gz notin D` by the `z` checks, since `g in <w>`). `F = sum_j gamma_j w_j`.

(a) *Gap/normalization.* Use `delta' = delta_U - 1/n0` (strictly inside the unique decoding radius; the reason is in (b)); `1 - delta'` differs from `1 - delta_U` by a relative `2^-12`, and the 40-query figure stays 33.2 bits. With `gamma_1 != 0` (probability `1 - 1/p`), `F/gamma_1` is uniform on the affine space `U = w_1 + span{w_2..w_317}` (in the notation of Thm 1.7, `u_0 = w_1` and `l = 316`; the error is independent of `l`, and dependence among the words does not matter since a uniform coefficient vector pushes forward to a uniform element of the image), and `Delta(F, V) = Delta(F/gamma_1, V)`.
If `Pr_gamma[Delta(F, V) <= delta_U] > eps_U + 1/p` then `Pr_U[...] > eps_U`, and Thm 1.7 gives **one** set `D'`, `|D'| >= (1 - delta') n0 > 4608`, and `v_j in V` with `v_j = w_j` on `D'` for all 317 words.

(b) *Claims are true evaluations.* The committed word `T_c` on `D` is an arbitrary vector of 8192 values; it is **not** assumed to be the evaluation of a polynomial (a reviewer suggested comparing with "the committed interpolation polynomial of degree `< N`"; that object exists only for an honest prover, so the argument below does not use it). Define `P_c := tz_c + (X - z) v_c` and `Q_c := tgz_c + (X - gz) v'_c`, where `v_c, v'_c in V` are the codewords of Thm 1.7 for the two quotient words of column `c`. Both have degree `<= N`, and by (a) both equal the word `T_c` on the **same** set `D'`, so `P_c(x) = T_c(x) = Q_c(x)` for all `x in D'`. They agree on `|D'| > 4608 > N` points, hence `P_c = Q_c` as polynomials, with `P_c(z) = tz_c` and `P_c(gz) = Q_c(gz) = tgz_c`. Thus **the claimed values are the evaluations of one polynomial `P_c` that coincides with the committed word on `D'`**. The same holds for `cp_i` with `R_i`. This is the statement used later; it is a statement about `P_c`, not about the word.

   *`P_c` is fixed by the roots.* The step "extraction is done before `z`" needs `P_c` not to depend on `gamma` or `z`. Any other polynomial `P'` of degree `<= N` that also agrees with the word `T_c` on a set of density `>= 1 - delta'` coincides with `P_c`: the two agreement sets overlap in at least `n0 (1 - 2 delta') = 1026 > N` points. This is where the strict `delta' < delta_U` is used (at `delta_U` the overlap is exactly `N = 1024`, which does not force equality for degree `<= N`). So `P_c, R_i` are functions of the committed words alone, hence fixed by `root_t`, `root_c` (given Merkle binding), before `alpha` (for `P_c`) and `z`.

(c) *Algebra.* (Excluded values of `z`: `0`, the `N` points of `H`, the `n0` points of `D`; hence the denominator `p - N - n0 - 1`. Field challenges are reduced from 768 bits mod `p`, bias at most `p/2^768 ~ 2^-517` per challenge, to be added in a full bound.) The violation row below is chosen in the trace committed by `root_t`, before `alpha` is drawn. The identity at `z` for the polynomials `P, R` holds only with probability `<= (4N + O(1))/(p - N - n0 - 1)` unless `CP_P = sum X^(Ni) R_i` as rational functions (degree bound re-derived for degree `<= N` is `4N + O(1)`, same order). Then, with `alpha` drawn after `root_t`, all transition constraints and boundary conditions hold for the `P_c` on the rows, except with probability `1/p`. So `P_c` is a valid trace, i.e. an extractable witness for the statement, up to the 82 padding rows.

(d) *Otherwise F is far.* If `Pr_gamma[Delta(F, V) <= delta_U] <= eps_U + 1/p`, then with probability `>= 1 - eps_U - 1/p`, `F` is `delta_U`-far from `V`, and FRI (Thm 7.2, with `delta = delta_U`) accepts with probability `<= eps_C + (1 - delta_U)^t`.

Single-attempt (interactive) error, unique decoding: `eps <= 1/p + (4N+O(1))/(p-N-n0) + (n0 + 1)/p + eps_C + (1 - delta_U)^40 + Merkle = 2^-33.2 (1 + tiny)`.

Caveats (what this argument does not cover): (i) it extracts a trace, not full knowledge soundness; (ii) it concerns the interactive protocol with Merkle binding assumed; (iii)
the argument uses that `FRI` tests degree `< N` while honest `F` has degree `<= N - 2`, which is fine for soundness (a larger code only weakens the checked statement, and (a)-(b) were done for the larger code); (iv) for `delta > delta_U` step (b) fails because `P_c` is not determined by the roots (the number of possible agreement sets multiplies the OOD error by a list-size factor that is not small enough across 160 columns), so the Johnson regime needs a different tool.

## 6. Fiat-Shamir and round-by-round soundness

- Garreta Thm 5.2 gives round-by-round (RBR) soundness for **FRI alone**, with `eps_i^fold ~ 2^-226` (per folding round, `m = 2`) and `eps^qry = (1 - min{theta, delta})^t`. [read]
- The outer rounds of this protocol (alpha, z, gamma) need their own RBR state function. **[derived, sketch only]** the natural one: state `1` after alpha iff the committed trace has no violated
  constraint-or-the combination vanishes (error `1/p`); after `z` iff the extracted `R_i` match (error `(4N+O(1))/(p-N-n0)`); after `gamma` iff `F` is `delta_U`-close to `V` (error `eps_U + 1/p`);
  then Garreta's folding and query states. The gluing of these state functions with Garreta's `State_theta` (which is defined for an oracle `f_0`, not for a function computed from two Merkle trees whose values are opened lazily) has **not** been proved or checked.
- If it holds, the informal Section 3.2 remark gives: success probability `<= sum_i Q_i eps_i <= Q_H max_i eps_i`, with `max_i eps_i = (1 - delta_U)^40 = 2^-33.2` for 40 queries, i.e. **33.2 - log2(Q_H) bits**. The SPEC's `log2(Q_H)` formula is therefore correct **conditional on** this RBR gluing and on the formal theorem
  RBR => Fiat-Shamir in the ROM ([CCH+19, Hol19]; not read).
- The ordinary-soundness route of BCS16 (state-restoration, `ssr <= C(b, k+1) s`, reconstructed) gives `~2^524` at `Q_H = 2^40` and is vacuous: the `log2(Q_H)` form really does need RBR.
- The transcript absorbs the statement hash first; this prevents reuse across statements but gives no extra grinding bits. Prover-side grinding of `b` bits is not implemented; if added it would add `b` bits against an adversary counted in hash evaluations.
- Query indices (`stark_core.Transcript.index`): `h <- SHA256(h || "i")`, `j0 = int(h) mod 4096`, so `j0` is exactly uniform given a uniform digest (4096 is a power of two). In the random-oracle model, index `i` is the output of the oracle on the previous digest (distinct inputs unless a state repeats, probability `<= Q_H^2/2^256`), so the 40 indices are independent uniform, matching the independent `s_j <- L_0` assumed by BCIKS Thm 7.2 and Garreta Constr. 4.4, **conditional on the model**. The chain is therefore not an obstacle; what remains is the formal write-up inside the RBR query-round state function, and note that each grinding attempt costs about 40 oracle calls (this only helps against the adversary and is not counted). Field challenges: 768 bits mod `p` (bias `2^-517`).

## 7. Corrected combined calculation (conditional arithmetic, not a bound)

Under the unique-decoding composition of section 5 and the RBR assumption of section 6:

`bits(t, Q_H) = 0.830 t - log2(Q_H)`, with every other error term below `2^-185`.

| Queries `t` | single attempt | `Q_H = 2^20` | `2^40` | `2^64` | `2^80` |
| --- | --- | --- | --- | --- | --- |
| 40 | 33.2 | 13.2 | -6.8 | -30.8 | -46.8 |
| 160 | 132.8 | 112.8 | 92.8 | 68.8 | 52.8 |

Queries needed, `ceil((lambda + log2 Q_H)/0.830)`: `lambda = 80`: 145 / 174 / 193; `100`: 169 / 198 / 217; `128`: 203 / 232 / 251 for `log2 Q_H = 40 / 64 / 80`.

Johnson-radius alternative (FRI alone, BCIKS Thm 7.2, `eta = sqrt(rho)/20`): `1.430` bits per query would give `ceil((lambda + log2 Q_H)/1.43)` queries, e.g. 98 for `lambda = 100`, `log2 Q_H = 40`. This row would apply to the protocol only after a
list-decoding DEEP/ALI step is established; it is **not** used for any parameter decision.

## 8. Classification

**Proved by a theorem I read (statement level; proofs not checked):** BCIKS Thm 1.7/1.2 (correlated agreement and gap, UD and Johnson); BCIKS Thm 7.2 (interactive FRI soundness with `eps_C` and `(1 - delta)^t`);
Garreta Thm 5.2 (RBR soundness of FRI for an oracle `f_0`, given MCA for Powers, Lemma 2.4 quoted from [BCH+25]).

**Derived by me, unreviewed:** section 5 (one DEEP step plus FRI, unique decoding); the RBR state-function sketch for the outer rounds; the numbers in sections 3, 4, 7.

**Conditional / open:** RBR gluing for the full protocol with lazily computed `f_0`; formal RBR => FS theorem (CCH+19/Hol19, unread); MCA for Powers (Lemma 2.4 is quoted from [BCH+25], unread);
a list-decoding DEEP/ALI step for any `delta > delta_U`; writing the chained index derivation into the query-round state function (uniform and, in the random-oracle model, independent: see section 6).

**Conjectural:** any exponent above the Johnson radius (the 3 bits/query, 120-bit row; BCIKS Conjecture 7.3 is the relevant statement for the FRI part).

**Not established by the implementation:** zero knowledge with 40 correlated queries plus Fiat-Shamir; SHA-256 as a random oracle; full knowledge soundness / extraction; the small-field attack literature (Fenzi 2025, unread) applies to small fields and the field here is 251 bits, but I have not read it.

## 9. Edits made to SPEC.md 3.4 (docs only) and still recommended

Made: `|F| ~ 2^251`, OOD `2^-239`; DEEP bullet references this audit and the 317-term/160-oracle distinction; Fiat-Shamir bullet made conditional; Johnson row relabelled "conditional"; 160-query target removed.
Done in revision 2: BCIKS theorem number corrected (7.2); Johnson row now cites that Thm 7.2 gives 57.2 bits for FRI alone, whole-protocol exponent stays 0.83 until a list-decoding DEEP step exists.
Still to do: a reviewer should check section 5 line by line; the RBR gluing and the index derivation need proofs or tests before any figure is called a bound.

## 10. Open questions for a reviewer

1. Is section 5(b) correct that Thm 1.7's common agreement set makes the two DEEP quotients of the same `T_c` consistent in unique decoding?
2. Does a state function exist for the whole protocol with lazily computed `f_0` and the stated per-round errors (Garreta Thm 5.2 is for an oracle `f_0`; Appendix A covers batched FRI by powers, not independent coefficients)?
3. Which list-decoding DEEP/ALI statement (BGKS Lemma 5.3, Haboeck 2022/1216, ethSTARK) covers `delta > delta_U` with 160 columns and two out-of-domain points, and what is its list-size term?
4. Does the exact Garreta Lemma 2.4 / [BCH+25] MCA error apply with `m = 2` and `|L|` equal to the current layer size? (I used `|L| <= 4096`.)
5. Is the random-oracle argument for the chained query indices (section 6) accepted as covering the independent-index assumption of Thm 7.2 / Thm 5.2?
