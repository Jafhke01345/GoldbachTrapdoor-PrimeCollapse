# Audit of SPEC.md section 3.4 against the cited theorems

Status: **unreviewed working audit. This is not a security claim.** The project does not prove the Goldbach conjecture and the
STARK is a toy, unaudited prototype. `QUERIES = 40`, `BLOWUP = 8` stay **experimental**; no code and no parameter was changed.

## 0. What could and could not be checked

Primary texts are not all available to me in this environment (eprint PDFs return `robots_disallowed`; fetched copies of BCIKS and
DEEP-FRI are truncated). Every statement below carries one of these tags:

- **[read]** I read the statement in a retrieved text this session.
- **[reconstructed]** assembled from a garbled or partial text; check against the typeset paper.
- **[not read]** I could not retrieve the text; the item is a question for the reviewer, not a finding.

| Source | Version used | Retrieved? |
| --- | --- | --- |
| BCIKS20, *Proximity Gaps for Reed-Solomon Codes* (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf), ECCC 2020/083 / eprint 2020/654 | text up to Section 5.2.6 / 6.1 | partial; **Section 7-8 (FRI soundness, Theorem 8.3, Conjecture 8.4) [not read]** |
| BGKS19/20, *DEEP-FRI: Sampling Outside the Box Improves Soundness* (arXiv 1903.12243, v1) | v1 | Theorem 4.1, Lemma 5.3, Protocol 5.4, Theorem 5.5 **[read]**; Section 6 truncated |
| BCS16, *Interactive Oracle Proofs* (Ben-Sasson, Chiesa, Spooner), Theorems 1-3 | eprint 2016/116 | **[reconstructed]** from a garbled PDF |
| Haboeck, *A summary on the FRI low degree test*, eprint 2022/1216 | - | abstract only **[not read]** |
| Garreta, *A simplified round-by-round soundness proof of FRI*, eprint 2025/1993 | - | title/abstract via search only **[not read]** |
| Fenzi, *Small-field hash-based SNARGs are less sound than conjectured*, eprint 2025/2197 | - | title via search only **[not read]** |
| ethSTARK documentation (soundness formulas, DEEP-ALI) | - | PDF blocked **[not read]** |
| BBHR18, *Fast Reed-Solomon Interactive Oracle Proofs of Proximity* (FRI) | - | **[not read]** |

Consequence: items 1 and 5 below can only be completed in part. The audit says where a reviewer must look.

## 1. Source identification and the statements actually used

1. **Proximity gaps (BCIKS20)** [read, Sections 1-5]. For RS[F, D, k] of rate rho = k/n with k+1 degree bound:
   - unique decoding (Theorem 1.2): for radius up to (1-rho)/2, correlated agreement for a random line/affine subspace fails with
     probability `eps_U = n/q` [read per my notes; exact quantifier "`delta < (1-rho)/2`" to be re-checked].
   - Johnson regime (Theorems 1.4-1.6, 5.2): radius up to `1 - sqrt(rho) - eta`, error
     `eps_J = (k+1)^2 (2 min(eta, sqrt(rho)/20))^7 / q` [reconstructed; the constant 7, the "20" and the exact `(k+1)` vs `(k+1)^2`
     must be checked]. The batching versions for `l` functions (Theorems 1.5/1.6) add a factor `l` or use powers of one challenge; **which
     form applies to independent coefficients `gamma_c` is not established here**.
   - Beyond Johnson: only Conjecture 8.4 / the "capacity" conjecture [not read].
2. **DEEP-FRI (BGKS)** [read].
   - Theorem 4.1 / Lemma 5.3: DEEP quotient with one out-of-domain point. If `f` is `delta`-far from degree `< d` then for any claimed
     value `v`, the quotient `(f - v)/(X - z)` is far from degree `< d - 1` except with probability governed by the list size at radius
     `delta` and `|F| - |D|`. Valid for `delta` below the Johnson-type radius only; the list-size term is quadratic in the list size.
   - Protocol 5.4 / Theorem 5.5: **a DEEP step in every FRI round**; `err_COMMIT <= r * nu*`, `err_QUERY <= (1 - delta* + (log n) eps)^l`.
     Per-invocation query error is `max{1 - delta, rho^(1/3)}` for the parameter range the theorem covers.
3. **BCS16** [reconstructed]. Theorem 2: IOP with state-restoration soundness `ssr(x, m)` gives a non-interactive argument in the ROM with
   soundness at most `ssr`; state-restoration soundness is bounded by `ssr <= C(b, k+1) * s` for a `k`-round IOP of soundness `s` and `b`
   oracle queries. Theorem 3 adds `3(m^2+1) 2^-lambda` for random-oracle collisions.

## 2. Parameter mapping

| Quantity (SPEC 3.4) | Value | Theorem notation | Match? |
| --- | --- | --- | --- |
| field | `p = 2^251 + 17*2^192 + 1`, `log2 p = 251.0` | `q` | SPEC writes `~2^252` and "`2^-240`"; correct values are `~2^251` and `2^-239.0` (cosmetic, conservative direction wrong by 1 bit) |
| trace length | `N = 1024` | degree bound `k + 1` (BCIKS: `k+1` coefficients) | RS degree `< N - 1` for `F` after one quotient: `k + 1 = 1023` |
| evaluation domain | `n0 = 8192` coset `3 <w>` | `n` / `|D|` | coset of a 2-power subgroup, closed under `x -> -x`: fine for arity-2 FRI |
| rate | `rho = (N-1)/n0 ~ 1/8` | `rho = k/n` | yes (slightly below 1/8, conservative) |
| blowup | 8 | `1/rho` | yes |
| constraint degree | 3, `k = 3` pieces, `CP` degree `<= 3N - 4` | - | OOD step is plain Schwartz-Zippel; no theorem needed |
| FRI | arity 2, 7 folds, final polynomial `< 8` coefficients, sent in clear | `r` rounds, final degree `d'` | rate stays 1/8 at the final layer (64 points, degree `< 8`); verifier must check final degree `<= 7` and consistency at queried points (it does) |
| DEEP | **one** DEEP step before plain FRI, batching 157 columns at `z` and `gz` plus 3 pieces | BGKS Protocol 5.4 has DEEP **per FRI round** | **mismatch**: Theorem 5.5 does not apply as stated; the closest results are Lemma 5.3/Theorem 4.1 for one DEEP step plus a plain-FRI theorem (BCIKS Thm 8.3 [not read]) |

## 3. Proximity-gap bounds instantiated (constants)

- `eps_U = n0/q = 2^13 / 2^251 = 2^-238` per application.
- `eps_J`, with `k+1 = 1024`, `eta` at its cap `sqrt(rho)/20 = 0.0177`: `2^20 * (0.0354)^7 / 2^251 = 2^-264.8` (reconstructed formula).
- OOD step: `(4N - 1)/(p - N - n0) = 2^-239.0`.
- Constraint combination: `1/p = 2^-251`.
- Merkle collisions in SHA-256 with `Q_H` hashes: `Q_H^2 / 2^257`; `2^-177` at `Q_H = 2^40`.
- FRI commit phase (7 rounds): `7 * n0/p ~ 2^-235` in unique decoding; Johnson regime has a larger term that I cannot instantiate [not read].

All field-dependent terms are below `2^-230` and are negligible next to the query term. **The security of the protocol is therefore
determined by the query-phase term and the Fiat-Shamir loss, not by the algebra.** This matches SPEC 3.4's qualitative claim.

## 4. Per-query exponent actually justified for rho = 1/8

| Regime | delta | per-query `-log2(1-delta)` | 40 queries | status |
| --- | --- | --- | --- | --- |
| unique decoding | 0.4375 | 0.830 | 33.2 bits | proof ingredients [read] (BCIKS Thm 1.2) plus plain-FRI query bound `(1-delta)^l` [not read, standard] |
| Johnson, per BCIKS | 0.646 | 1.5 | 60 bits | **only if** BCIKS Thm 8.3 gives `(1 - delta)^l` up to `delta = 1 - sqrt(rho) - eta` [not read] |
| Johnson, per DEEP-FRI Thm 5.5 | - | `-log2 max{1-delta, rho^(1/3)}` = **1.0** (`rho^(1/3) = 0.5`) | 40 bits | [read], but Theorem 5.5 is for per-round DEEP, which is not what is implemented |
| capacity | 0.875 | 3 | 120 bits | conjecture; **and** a recent paper title suggests it fails for small fields [not read]; field here is 251 bits, so applicability must be checked |

Mismatch with SPEC 3.4: the table row "Johnson radius (proved, ...)" says 1.5 bits per query. With the one source I read in full the
per-query exponent for `rho = 1/8` is **1.0 bit** (the `rho^(1/3)` floor), giving **40 bits**, not 60. 60 bits is at best a
conditional statement about BCIKS Theorem 8.3. Revise the row label from "proved" to "proved if Theorem 8.3 gives ... [unchecked]".

## 5. Do DEEP and FRI compose as SPEC 3.4 says?

SPEC 3.4 "DEEP and low degree" bullet says that `F` is far from RS except with probability `eps_gap`, "then FRI accepts ... with probability at
most `(1-delta)^40` plus commit-phase terms". Problems:

1. **Batching count (corrected).** Three different numbers exist and must not be interchanged:
   - 160 distinct committed oracles: 157 trace columns `T_c` (root_t) and 3 pieces `cp_i` (root_c);
   - **317 terms in `F`**, each with its own independent coefficient: 157 `(T_c - tz_c)/(X - z)` (gamma_c), 157 `(T_c - tgz_c)/(X - gz)`
     (gamma2_c), 3 `(cp_i - cz_i)/(X - z)` (delta_i). These are 317 words on `D` computed by the verifier from Merkle openings;
   - the earlier "163" in this audit was an arithmetic error and is withdrawn.
   What the theorem's batching parameter `l` counts is **not established**: BCIKS Theorems 1.5/1.6 are stated for `l` words `f_1..f_l`
   combined with a random challenge (powers of one challenge or independent coefficients; to be read in the typeset statement). If it counts
   the words being combined, the substitution is `l = 317`, each word being a quotient that has degree `< N - 1` when the claimed
   value is correct; if the proof needs the 160 underlying oracles (for example because the two quotients of the same `T_c` are not
   independent words), `l = 160` or a two-point extension is needed. Open until the exact statement is read. Order of magnitude: any
   factor `l * k` is `< 2^19`, so `eps` stays `< 2^-210` in either reading.
2. The "claimed values are the true evaluations" step (BGKS Lemma 5.3 / Theorem 4.1) has an extra list-size term and a radius condition.
   SPEC 3.4 folds it into one `eps_gap`. Write it as a separate term `eps_deep = (list size)^2 / (p - n0 - N)`; in unique decoding
   the list size is 1.
3. Applying DEEP once and then plain FRI is not the DEEP-FRI protocol. Theorem 5.5's `err_COMMIT <= r * nu*` is per-round DEEP; do not cite
   it for this configuration. Use Lemma 5.3 for the DEEP step and a plain-FRI soundness theorem for the rest.
4. SPEC 3.4's use of the proximity radius `delta` for both the DEEP step and the FRI query exponent is correct only if the **same**
   radius is used in both; the Johnson-radius row needs the DEEP step's list-size term as well.

## 6. Fiat-Shamir model and grinding

SPEC 3.4 "Fiat-Shamir" bullet: "round-by-round soundness gives (by a union bound over the adversary's attempts) ... at most `Q_H` times the
single-attempt error ... costs `log2(Q_H)` bits".

- This is a correct consequence of **round-by-round (RBR) soundness** (Canetti et al.; Chiesa-Manohar-Spooner) for the ROM, with the
  error being the **maximum over rounds** of the RBR error. It is **not** a consequence of ordinary soundness of the interactive protocol.
- What I have verified [reconstructed]: the BCS16 route (state-restoration soundness) gives `ssr <= C(b, k+1) s`. With `k` about 13
  rounds (alpha, z, gamma, 7 betas, queries) and `b = Q_H`: `C(2^40, 14)` is `2^524`, and `C(2^64, 14)` is `2^860`. That bound is
  **vacuous** for every realistic `s`. The `log2(Q_H)` form therefore **needs an RBR theorem for this exact protocol**.
- Whether FRI/DEEP-ALI is RBR sound with the errors above is the content of recent work (Garreta, eprint 2025/1993 [not read]; the
  ethSTARK documentation [not read]). The implementation as a whole (157-column batching, one DEEP step, 7 folds, 40 queries from one
  transcript) has not been shown RBR sound by any source I read.
- The statement "does not multiply the security bits by the number of hashes" is correct; "costs `log2(Q_H)` bits" is conditional.
- Statement hashing: the transcript absorbs the statement hash first, so the challenges depend on `C`; this prevents reuse across
  statements but gives no extra bits against grinding on one statement.
- Grinding (prover-side proof of work) of `b` bits before the query indices would raise the cost per attempt to `2^b` hashes and
  therefore adds `b` bits against an adversary measured in hash evaluations. It is not implemented; SPEC's sentence "adding grinding would
  move the proved bound" is accurate.
- ROM-collision term `3(m^2+1) 2^-lambda` [reconstructed]: with SHA-256, `lambda = 256`; negligible.

## 7. Corrected combined calculation (for the current parameters; not a claim)

Single-attempt error in the unique-decoding regime (every term from sections 3-4):

`eps_1 = 2^-33.2 (queries) + 2^-235 (FRI commit) + 2^-238 (proximity gap) + 2^-239 (OOD) + 2^-251 (combination) + merkle = 2^-33.2 (1 + tiny)`.

Bits against an adversary with `Q_H` hash evaluations, **if** the RBR assumption of section 6 holds: `bits = -log2(eps_1) - log2(Q_H)`.

| Queries | per-query bits | `Q_H = 2^20` | `2^40` | `2^64` | `2^80` |
| --- | --- | --- | --- | --- | --- |
| 40, unique decoding (0.83) | 33.2 | 13.2 | **-6.8** | -30.8 | -46.8 |
| 160, unique decoding | 132.8 | 112.8 | 92.8 | 68.8 | 52.8 |
| 160, Johnson 1.0-bit (DEEP-FRI floor, unverified applicability) | 160 | 140 | 120 | 96 | 80 |

Queries needed for a target of `lambda` bits against `Q_H` hash evaluations (unique decoding, `ceil((lambda + log2 Q_H)/0.83)`):

| lambda \ log2 Q_H | 40 | 64 | 80 |
| --- | --- | --- | --- |
| 80 | 145 | 174 | 193 |
| 100 | 169 | 198 | 217 |
| 128 | 203 | 232 | 251 |

Reading: **40 queries do not reach even 33 bits against a `2^40` adversary under proved unique decoding** (and the claim of about 120
bits needs the capacity conjecture). SPEC 3.4's provisional "160 queries ... leaving room for `log2(Q_H)`" is accurate only for
`Q_H` up to about `2^32` if the target is 100 bits; against `2^64` it gives about 69 bits in unique decoding. The number 160 should not be
described as a target until the theorem questions in section 8 are closed.

## 8. Classification

**Proved (given the cited theorem statements are as I recorded them):** Schwartz-Zippel steps (combination `1/p`, OOD `(4N-1)/(p-N-n0)`),
unique-decoding proximity-gap term `n0/p`, constraint-degree bookkeeping, `ZK` argument is a sketch (not proved).

**Conditional on a theorem I could not read:** the plain-FRI soundness statement with query exponent `(1 - delta)^l` at the Johnson
radius (BCIKS Theorem 8.3), the list-size term for the DEEP step beyond unique decoding, the batching constant for the 317-term DEEP combination (what `l` counts is open)
with independent coefficients, round-by-round soundness of the whole protocol.

**Conjectural:** any per-query exponent above the Johnson radius (the 120-bit row), and the capacity-regime applicability at this
field size.

**Not established by the implementation:** the Fiat-Shamir loss `log2(Q_H)` (needs an RBR theorem for this protocol); zero knowledge
under 40 correlated queries plus Fiat-Shamir; that SHA-256 behaves as a random oracle for Merkle binding and transcript; that the
verifier's checks equal the theorem's verifier (final-degree check, domain membership of queried indices, `j0` sampling with
replacement); that no cheating prover profits from the weaker factor-q condition beyond SPEC section 3.3's lemma.

## 9. Edits to SPEC.md 3.4 recommended by this audit

1. "`|F| = p ~ 2^252`" and "about `2^-240`": replace by `p ~ 2^251`, `2^-239`.
2. "DEEP and low degree" bullet: split into (a) batching gap (BCIKS Thm 1.5/1.6; `l` = 317 terms or 160 oracles, open), (b) DEEP OOD step (BGKS Lemma 5.3, list-size
   term), (c) plain-FRI commit and query terms; state that the implementation is one DEEP step plus plain FRI, **not** DEEP-FRI Protocol 5.4.
3. "Fiat-Shamir" bullet: state that the `log2(Q_H)` loss requires round-by-round soundness for this protocol, that BCS16's
   state-restoration route gives a vacuous bound at these parameters, and that RBR soundness has not been checked for it.
4. Table: relabel the Johnson row "proved only if BCIKS Thm 8.3 [unchecked]; DEEP-FRI per-query floor `rho^(1/3)` gives 1.0 bit / 40 bits".
5. "Parameter status": 160 is not a target; the query count is to be fixed after the questions in section 8 are closed.

## 10. Open questions for a reviewer

1. Exact statement and conditions of BCIKS Theorem 8.3 (and Conjecture 8.4): does the query term equal `(1 - delta)^l` up to the Johnson radius
   for arity-2 folding with `rho = 1/8`?
2. Exact `eps_J` constant and the multi-function batching bound for independent random coefficients.
3. A theorem (or counterexample) for round-by-round soundness of "one DEEP step followed by FRI" over a 251-bit field.
4. Whether the 2025 work on small-field hash-based SNARGs affects any regime used here (field is large, so probably not).
5. Whether the final polynomial being sent in clear (`< 8` coefficients) changes the commit-phase error.
