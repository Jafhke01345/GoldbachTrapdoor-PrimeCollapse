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
- Out-of-domain identity: `4N/(p - N - n0 - 1) ~ 2^-239`.
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
If `Pr_gamma[Delta(F, V) <= delta'] > eps_U + 1/p` (the event is at `delta'`, not `delta_U`: closeness to `delta_U` does not imply closeness to `delta'`) then `Pr_U[...] > eps_U`, and Thm 1.7 gives **one** set `D'`, `|D'| >= (1 - delta') n0 > 4608`, and `v_j in V` with `v_j = w_j` on `D'` for all 317 words.

(b) *Claims are true evaluations.* The committed word `T_c` on `D` is an arbitrary vector of 8192 values; it is **not** assumed to be the evaluation of a polynomial (a reviewer suggested comparing with "the committed interpolation polynomial of degree `< N`"; that object exists only for an honest prover, so the argument below does not use it). Define `P_c := tz_c + (X - z) v_c` and `Q_c := tgz_c + (X - gz) v'_c`, where `v_c, v'_c in V` are the codewords of Thm 1.7 for the two quotient words of column `c`. Both have degree `<= N`, and by (a) both equal the word `T_c` on the **same** set `D'`, so `P_c(x) = T_c(x) = Q_c(x)` for all `x in D'`. They agree on `|D'| > 4608 > N` points, hence `P_c = Q_c` as polynomials, with `P_c(z) = tz_c` and `P_c(gz) = Q_c(gz) = tgz_c`. Thus **the claimed values are the evaluations of one polynomial `P_c` that coincides with the committed word on `D'`**. The same holds for `cp_i` with `R_i`. This is the statement used later; it is a statement about `P_c`, not about the word.

   *`P_c` is fixed by the roots.* The step "extraction is done before `z`" needs `P_c` not to depend on `gamma` or `z`. Any other polynomial `P'` of degree `<= N` that also agrees with the word `T_c` on a set of density `>= 1 - delta'` coincides with `P_c`: the two agreement sets overlap in at least `n0 (1 - 2 delta') = 1026 > N` points. This is where the strict `delta' < delta_U` is used (at `delta_U` the overlap is exactly `N = 1024`, which does not force equality for degree `<= N`). So `P_c, R_i` are functions of the committed words alone (given Merkle binding). Timing: the `P_c` are fixed by `root_t`, before `alpha`; the `R_i` are fixed by `root_c`, which is sent after `alpha` but before `z`.

(c) *Algebra.* (Excluded values of `z`: `0`, the `N` points of `H`, the `n0` points of `D`; hence the denominator `p - N - n0 - 1`. Field challenges are reduced from 768 bits mod `p`, bias at most `p/2^768 ~ 2^-517` per challenge, to be added in a full bound.) The violation row below is chosen in the trace committed by `root_t`, before `alpha` is drawn. The identity at `z` for the polynomials `P, R` holds only with probability `<= 4N/(p - N - n0 - 1)` unless `CP_P = sum X^(Ni) R_i` as rational functions (degree bound re-derived for degree `<= N` is `4N`, same order). Then, with `alpha` drawn after `root_t`, all transition constraints and boundary conditions hold for the `P_c` on the rows, except with probability `1/p`. So `P_c` is a valid trace, i.e. an extractable witness for the statement, up to the 82 padding rows.

(d) *Otherwise F is far.* If `Pr_gamma[Delta(F, V) <= delta'] <= eps_U + 1/p`, then with probability `>= 1 - eps_U - 1/p`, `F` is `delta'`-far from `V`, and FRI (Thm 7.2, with `delta = delta'`) accepts with probability `<= eps_C + (1 - delta')^t`. Numerically `-40 log2(1 - delta') = 33.187` bits versus `33.200` at `delta_U`.

Single-attempt (interactive) error, unique decoding: `eps <= 1/p + 4N/(p-N-n0-1) + (n0 + 1)/p + eps_C + (1 - delta')^40 + Merkle = 2^-33.19 (1 + tiny)`.

Caveats (what this argument does not cover): (i) it extracts a trace, not full knowledge soundness; (ii) it concerns the interactive protocol with Merkle binding assumed; (iii)
the argument uses that `FRI` tests degree `< N` while honest `F` has degree `<= N - 2`, which is fine for soundness (a larger code only weakens the checked statement, and (a)-(b) were done for the larger code); (iv) for `delta > delta_U` step (b) fails because `P_c` is not determined by the roots (the number of possible agreement sets multiplies the OOD error by a list-size factor that is not small enough across 160 columns), so the Johnson regime needs a different tool.

## 6. Fiat-Shamir and round-by-round soundness

- Garreta Thm 5.2 gives round-by-round (RBR) soundness for **FRI alone**, with `eps_i^fold ~ 2^-226` (per folding round, `m = 2`) and `eps^qry = (1 - min{theta, delta})^t`. [read]
- The outer rounds of this protocol (alpha, z, gamma) need their own RBR state function. **[derived, sketch only]** the natural one: state `1` after alpha iff the committed trace has no violated
  constraint-or-the combination vanishes (error `1/p`); after `z` iff the extracted `R_i` match (error `4N/(p-N-n0-1)`); after `gamma` iff `F` is `delta'`-close to `V` (error `eps_U + 1/p`);
  then Garreta's folding and query states. The gluing of these state functions with Garreta's `State_theta` (which is defined for an oracle `f_0`, not for a function computed from two Merkle trees whose values are opened lazily) has **not** been proved or checked.
- If it holds, the informal Section 3.2 remark gives: success probability `<= sum_i Q_i eps_i <= Q_H max_i eps_i`, with `max_i eps_i = (1 - delta')^40 = 2^-33.19` for 40 queries, i.e. **about 33.2 - log2(Q_H) bits**. The SPEC's `log2(Q_H)` formula is therefore correct **conditional on** this RBR gluing and on the formal theorem
  RBR => Fiat-Shamir in the ROM ([CCH+19, Hol19]; not read).
- The ordinary-soundness route of BCS16 (state-restoration, `ssr <= C(b, k+1) s`, reconstructed) gives `~2^524` at `Q_H = 2^40` and is vacuous: the `log2(Q_H)` form really does need RBR.
- The transcript absorbs the statement hash first; this prevents reuse across statements but gives no extra grinding bits. Prover-side grinding of `b` bits is not implemented; if added it would add `b` bits against an adversary counted in hash evaluations.
- Query indices (`stark_core.Transcript.index`): `h <- SHA256(h || "i")`, `j0 = int(h) mod 4096`, so `j0` is exactly uniform given a uniform digest (4096 is a power of two). In the random-oracle model, index `i` is the output of the oracle on the previous digest (distinct inputs unless a state repeats, probability `<= Q_H^2/2^256`), so the 40 indices are independent uniform, matching the independent `s_j <- L_0` assumed by BCIKS Thm 7.2 and Garreta Constr. 4.4, **conditional on the model**. The chain is therefore not an obstacle; what remains is the formal write-up inside the RBR query-round state function, and note that each grinding attempt costs about 40 oracle calls (this only helps against the adversary and is not counted). Field challenges: 768 bits mod `p` (bias `2^-517`).

### 6A. Virtual oracle `F` and the Garreta query round (derived; the state-function gluing below is a sketch, not a proof)

**What Garreta's query analysis depends on.** In Thm 5.2 the query-round probability is `(|AccQueries|/|L_0|)^t` (their equation (9)) where
`AccQueries = { z in L_0 : for all i, Fold(f_{i-1}, m_i, alpha_i)(z^(i)) = f_i(z^(i)) }` for the **fixed** functions `f_0, ..., f_k` and challenges `alpha_i`.
Everything after that (Claims 5.3-5.5, the case split on the sets `W_i`) is a statement about this set and about `Delta(f_0, C_0)`. It does not use how `f_0` is represented,
only that `f_0` is a fixed function `L_0 -> F` before the query indices are sampled. This is why lazy evaluation is not by itself an obstacle.

**Virtual-oracle lemma (derived).** Once `root_t`, `root_c`, the claims `tz, tgz, cz` and the DEEP coefficients are fixed (all before the first folding challenge), the function
`F(x) = sum_c gamma_c (T_c(x) - tz_c)/(x - z) + sum_c gamma2_c (T_c(x) - tgz_c)/(x - gz) + sum_i delta_i (cp_i(x) - cz_i)/(x - z)`, `x in D`, is a total function of the two committed
vectors and the fixed values (denominators are nonzero since `z, gz notin D`). The verifier's value at a query position `j` is computed from the `W + k` entries it
opens at leaf `j` of the two trees. Hence: *except on a Merkle-binding failure event, every accepted opening at position `j` returns the leaf values of the committed vectors, so the verifier's value at `j` equals `F(x_j)` for the single virtual `F`.*
In the IOP model that BCS16 compiles, `T` and `cp` are oracles and `F` is a function the verifier evaluates with two position queries per point (one pair `j0`, `j0 + n0/2`).

**Predicate comparison (implementation `stark_core.verify` against Garreta Construction 4.4).**

| Item | Implementation | Construction 4.4 / Thm 5.2 | Matches |
| --- | --- | --- | --- |
| `f_0` | virtual `F` on `L_0 = D` (coset `3<w>`) | oracle `f_0` on a coset | yes (virtual oracle, above) |
| block of query `s` | positions `j0` and `j0 + n0/2` = `x` and `-x` (`om^(n0/2) = -1`) | `Block(L_0, 2, s^2) = {s, -s}` | yes |
| fold | `(a + b)/2 + beta (a - b)/(2x)` | `Fold(f, 2, alpha)(x^2) = p_{f,x^2}(alpha)`, `p` the degree `< 2` interpolant through `(x, a), (-x, b)` | yes (algebra: `c_0 = (a+b)/2`, `c_1 = (a-b)/(2x)`) |
| local fold checks | layer `l` value compared with `Fold` of layer `l-1` at the block, layers 1..6 against committed leaves, layer 7 against `final(x)` | `Fold(f_{i-1}, m_i, alpha_i)(s^(i)) = f_i(s^(i))`, `i = 1..k`, `k = 7` | yes |
| final check | `final` has exactly 8 coefficients, so `f_7 in C_7`; compared at the folded point | `f_k` read in full, `f_k in C_k` | yes |
| challenge order | `beta_l` drawn after the previous root is absorbed; `final` absorbed before the indices | `alpha_i` before `f_i`; queries last | yes (checked in the transcript order of `verify`) |
| query sampling | 40 indices `j0`, uniform given the oracle, chained (section 6) | `s_1..s_t <- L_0` independent | yes in the random-oracle model |
| acceptance | all 40 chains pass | `s_j in AccQueries` for all `j` | yes: `AccQueries` is closed under `z -> -z`, and uniform `j0` on `[0, n0/2)` induces the same acceptance probability `(|AccQueries|/n0)^t` |

So the query round of the implementation equals the query round of Theorem 5.2 for the virtual `F`, with parameters `theta` free (to be set to `delta'`), folding factors `m_i = 2`, `k = 7`, `t = 40`. I checked this by reading
the verifier, not by a machine check; the completeness tests of the repository exercise the same arithmetic.

**Separate failure events (not absorbed into Garreta's theorem).** (i) Merkle binding / collision (random oracle, `Q_H^2/2^257`); (ii) the extraction of the oracles from the Merkle trees in the BCS16 compilation (standard; BCS16 Theorem 2/3 additive term, reconstructed, unread in typeset form).

**State function for the whole protocol (sketch).** Order of messages: `root_t`, `alpha`, `root_c`, `z`, claims `(tz, tgz, cz)`, `gamma`, `beta_1`, root_1, ..., `beta_7`, `final`, query indices.
Verifier rounds and their lucky-event errors (state starts 0 for a false statement; it never goes back to 0):

| Round | State becomes 1 iff | Error | Source |
| --- | --- | --- | --- |
| `alpha` | the `delta'`-close polynomials `P_c` of `root_t` exist, violate a constraint or boundary, yet all residues of `CP_P` cancel | `1/p` | linear form in `alpha` (SPEC 3.4) |
| `z` | `P_c`, `R_i` exist and `CP_P != sum X^(Ni) R_i` as rational functions but the identity holds at `z` | `4N/(p - N - n0 - 1)` | Schwartz-Zippel |
| `gamma` | `F` is `delta'`-close to `V` although `P`, `R` fail to exist or a claim is not the evaluation of them | `eps_U + 1/p` | BCIKS Thm 1.7 plus 5(a)-(b) |
| `beta_l`, `l = 1..7` | Garreta's `State_theta`, `theta = delta'`, `f_0 = F` (only entered when `F` is `delta'`-far) | `eps_mca(C_l, 2, delta') ~ 2^-226` | Garreta Thm 5.2, Lemma 2.4 |
| query | all `s_j in AccQueries` while `F` is `delta'`-far | `(1 - delta')^40` | Garreta Thm 5.2 |

Why the pieces should fit: (1) if `F` is `delta'`-close and the `gamma` flip did not occur, then `P`, `R` exist and the claims are the true evaluations; the verifier's identity check at `z` then fails unless the `z` or `alpha` flip occurred, so a state-0 transcript is rejected; (2) if `F` is `delta'`-far, Garreta's state governs and a state-0 full transcript is rejected by Garreta's theorem.
Each flip depends only on the transcript up to the verifier's message (claims precede `gamma`), so "prover moves" does not change the state.

**Not proved.** (a), (b) These two items (the four properties of Definition 3.4 and the hand-over to `State_theta`) are now addressed by section 6B, as a derivation that nobody but me has read.
(c) The formal theorem RBR => Fiat-Shamir in the ROM ([CCH+19, Hol19], unread) and the BCS16-style extraction of the oracles. (d) Zero knowledge is unaffected by this section.

Status table:

| Claim | Status |
| --- | --- |
| `F` is a total function fixed before the folding challenges | derived (from message order) |
| Every accepted opening evaluates that same `F`, except on a binding failure | derived, conditional on Merkle binding |
| The verifier's query/acceptance predicate equals Garreta's `AccQueries` predicate | checked by reading code, table above |
| Garreta's query-round bound applies to this predicate | follows from Thm 5.2 as stated, given the previous row (proof not checked) |
| The outer state function composes with Garreta's `State_theta` (Definition 3.4) | derived in 6B, unreviewed |
| Formal RBR => Fiat-Shamir, and extraction from Merkle trees | **open** (sources unread) |

### 6B. Outer state function, defined round by round, and the four properties of Garreta Definition 3.4 (derived; unreviewed)

Setting: the interactive IOP obtained from the protocol, statement `S` = "the AIR has a valid trace for this public input" (the link from this statement to "n is prime and committed in C" is the circuit lemma of section 3.3 of SPEC.md and is not part of this audit). Only statements with `S` false matter; for `S` true set `State = 1` everywhere.
Messages in order: `T` (root_t, the word on `D`), `alpha`, `C` (root_c), `z`, claims `(tz, tgz, cz)`, `gamma`, `beta_1`, `f_1`, ..., `beta_6`, `f_6`, `beta_7`, `final`, query indices `(j_1..j_40)`. Malformed prover messages (wrong length or domain) make the verifier reject and are treated as outside the message space.

**Candidate polynomials (prefix-determined, unique).** Let `delta' = 0.4375 - 1/8192`. For a word `X` on `D`, let `Cand(X)` be the set of polynomials of degree `<= N` agreeing with `X` on at least `n0 (1 - delta')` points. Two distinct members would agree with each other on at least `n0 (1 - 2 delta') = 1026 > N` points, impossible, so `|Cand(X)| <= 1`.
`P_c := Cand(T_c)` and `R_i := Cand(C_i)` (columns of `T`, pieces of `C`), each possibly undefined (`bottom`). They depend on the word alone, hence `P` is determined by the transcript at `T`, before `alpha`, and `R` at `C`, before `z`; no later message is used.
`Valid(P)`: the polynomials `P_c` satisfy every transition constraint on every active row and every boundary condition. Since `S` is false, `Valid(P)` fails for **every** family `P` (a valid family of any degree `<= N` is a witness trace). `Defined_T` (all `P_c` defined), `Defined_C` likewise.
`Q_alpha := A(X) sum_i alpha_i C_i(P, P(gX), pub) / (X^N - 1) + sum_b alpha_(m+b) (P_(c_b) - v_b)/(X - g^(r_b))`, a rational function.
`Delta := Q_alpha - sum_i X^(Ni) R_i`.
`Consistent` := `Defined_T` and `Defined_C` and `tz_c = P_c(z)`, `tgz_c = P_c(gz)`, `cz_i = R_i(z)` for all `c, i`.
`F` is the virtual oracle of 6A and `V = RS[F, D, N]` (degree `< N`).

**State function** (starts at 0 and, once 1, stays 1 by definition; a prover message never changes it):
1. `State(empty) = 0` (`S` false).
2. After `alpha`: becomes 1 iff `Defined_T` and `Q_alpha` has no pole. Error: `Defined_T` and `S` false give an active row `r` where some constraint or boundary fails; the residue of `Q_alpha` at `g^r` is a linear form in `alpha` with at least one nonzero coefficient, so `Pr_alpha[no pole] <= 1/p`. **`eps_alpha = 1/p`.**
3. After `z`: becomes 1 iff `Defined_T`, `Defined_C`, `Delta != 0` and `Delta(z) = 0`. Error: if the state was 0, `Defined_T` and `S` false force a pole of `Q_alpha`, so `Delta != 0`; `(X^N - 1) Delta` is a nonzero polynomial of degree `<= 4N` (numerator of the transition term `<= 4N - 1`; boundary terms `<= 2N - 1`; `X^(Ni) R_i (X^N - 1)` has degree `<= 4N` because `deg R_i <= N`), and `z` is uniform on `Z = F \ ({0} + H + D)`, `|Z| >= p - N - n0 - 1`. **`eps_z = 4N/(p - N - n0 - 1)`.** (Earlier sections wrote the degree bound as `4N + O(1)`; the count above gives exactly `4N`, so the sharper value applies.)
4. After `gamma`: becomes 1 iff `F` is `delta'`-close to `V` and not `Consistent`. Error: if not `Consistent`, then `Pr_gamma[Delta(F, V) <= delta'] <= eps_U + 1/p`, since otherwise 5(a)-(b) give `Consistent` (they show that `T_c` and `C_i` have candidate polynomials in `Cand(.)` and that the claims are their evaluations; here `Cand` membership holds because the extracted polynomial agrees with the word on `D'`, `|D'| >= n0 (1 - delta')`). The words `w_j` depend on `T, C, z`, claims only (all before `gamma`). **`eps_gamma = n0/p + 1/p`.**
5. After `beta_1..beta_7` and the query round: if `F` is `delta'`-close, no flips (error 0). If `F` is `delta'`-far, use Garreta's `State_theta` with `theta = delta'` and `f_0 = F` on the suffix `(beta_1, f_1, ..., beta_7, final, queries)`. Then `eps_(beta_l) = eps_mca(C_l, 2, delta')`, about `2^-226` (Lemma 2.4), and `eps_query = (1 - min{delta', Delta(F, C_0)})^40 = (1 - delta')^40`.
   The branch (`F` close or far) is decided by the prefix up to `gamma`, so each flip depends only on the transcript at that verifier message.

**The four properties (Definition 3.4), checked for `S` false.**
- *Empty transcript:* `State(empty) = 0` for `S` false, `1` for `S` true. Holds by definition.
- *Prover moves:* the state is only updated at verifier messages (items 2-5); a prover message leaves it unchanged. In the far branch the Garreta state satisfies the same property for the folded oracles `f_l` and `final` (his Definition 3.4). Holds.
- *Default:* flips are 0 to 1 only; Garreta's state has the same property; once 1 the state is 1 on every extension. Holds.
- *Full transcript:* take a full transcript with state 0. (a) `F` `delta'`-far: Garreta's full-transcript property for `State_theta(F, .)` gives that his verifier rejects; our verifier applies the same fold, final-degree and query checks (table in 6A) plus further checks, so it rejects. (b) `F` `delta'`-close: the `gamma` flip did not occur, so `Consistent`; then the verifier's left side equals `Q_alpha(z)` (it substitutes `tz = P(z)`, etc.) and its right side equals `sum z^(Ni) R_i(z)`; the identity holds iff `Delta(z) = 0`. State 0 at `alpha` with `Defined_T` and `S` false gives `Delta != 0`, and State 0 at `z` gives `Delta(z) != 0` (if `Delta(z) = 0` the `z` flip would have occurred). So the identity check fails and the verifier rejects. Holds.

**Hand-over to Garreta.** Garreta's `State_theta(f_0, empty) = 1` iff `f_0 in C_0`. In the far branch `F` is `delta'`-far, hence not a codeword, so the initial state is 0, as his analysis requires. The hypotheses he needs are only that `f_0` is a fixed function before `beta_1` (true, 6A) and `theta` is a free parameter. The near branch never enters his state function.

**Result (derived).** The protocol has round-by-round soundness for `S` false with the error list `1/p`, `4N/(p - N - n0 - 1)`, `(n0 + 1)/p`, `eps_mca ~ 2^-226` (seven rounds), `(1 - delta')^40`. Maximum: `(1 - delta')^40 = 2^-33.19`. Everything else is below `2^-185`.

**Assumptions used.** BCIKS Thm 1.7 (UD) as stated; Garreta Thm 5.2 including his Lemma 5.1 (applies to every fixed prefix) and the MCA error of Lemma 2.4 (quoted from [BCH+25], unread); the random-oracle model for Merkle binding.

**Not shown here.** (1) The formal theorem that RBR soundness of an IOP gives soundness of its BCS-compiled, Merkle-tree based Fiat-Shamir argument with loss `sum Q_i eps_i`, including extraction of the oracles from the trees (the sources are not read: BCS16 in typeset form, CCH+19, Hol19). (2) That `eps_mca` of Lemma 2.4 applies with the exact layer sizes. (3) Independent review of the proofs of the theorems used. (4) The link from `S` to primality. (5) Zero knowledge.
A Lean formalization of Garreta's proof is mentioned by the authors (Hirai); I have not read it. It could be used to check the hand-over assumptions of this section.

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
a list-decoding DEEP/ALI step for any `delta > delta_U`; review of the outer state function and its Definition 3.4 check (section 6B); writing the chained index derivation into the query-round state function (uniform and, in the random-oracle model, independent: see section 6).

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
