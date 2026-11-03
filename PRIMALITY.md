# Zero-Knowledge Primality via Pocklington Chains (design note)

**Status: design document, plus a working prototype for numbers below 2^64.** The repo contains a *public*
reference verifier (`pocklington_chain.py`), a prototype of the commitment and range-proof layers
(`zkrp_toy.py`), and `stark_primality.py`, a hash-based STARK that implements the circuit of section 2 for a
hidden `n < 2^64` (see section 7). The cost figures in section 4 refer to the 1024-bit case, are rough
estimates, and are not measurements.

## Goal

Extend the range proof so that the hidden endpoints $a$ and $b$ are also proven **prime**,
without revealing them.

## 1. Why Pocklington instead of Pratt

A Pratt certificate needs a complete factorization of $n-1$. For a random 1024-bit prime that
is infeasible. Pocklington's criterion only needs a *half-size* factored part:

Let $n = F \cdot R + 1$ with $F > \sqrt{n}$ and $F$ completely factored. If there is a base $a$ with

1. $a^{n-1} \equiv 1 \pmod n$, and
2. $\gcd\!\left(a^{(n-1)/f} - 1,\; n\right) = 1$ for every prime factor $f \mid F$,

then $n$ is prime.

The prover builds primes bottom-up with $F = 2q$, where $q$ is an already-proven smaller prime
and $R < q$ (so $F^2 > n$). Each level roughly doubles the bit length:

```text
[ base prime, ~17 bits ]      checked directly (small table / deterministic test)
          |
          v
[ level 1 ]  n_1 = 2 * q_0 * R_1 + 1      assert 4 * q_0^2 > n_1
          |
          v
[ level k ]  n_k = 2 * q_(k-1) * R_k + 1  the top value n_k is the secret endpoint
```

Side effect: primes generated this way are not uniformly distributed among all primes of that
size. Do not describe the anonymity set as "uniform".

`pocklington_chain.py` generates such chains and verifies them (about 9 ms for a 1024-bit
chain in a pure-Python run). The certificate **reveals** $n$, so on its own it is a
*witness*, not a zero-knowledge proof.

## 2. Mapping the check into a circuit

Inside a SNARK framework (e.g. `arkworks`, `halo2`, or `circom`):

- **Public inputs:** the commitments $C_a$, $C_b$ and the median $c$.
- **Private witness:** the chain values $(q_i, R_i, a_i)$, the Bezout witnesses $w_i$ below, and the commitment randomness.

Per-level constraints:

| Constraint | Meaning | Cost driver |
|---|---|---|
| $n_i - 2 q_i R_i - 1 = 0$ | chain structure | big-integer multiplication |
| $R_i < q_i$ | guarantees $F^2 > n_i$ | bit-decomposition range check |
| $u_i = a_i^{(n_i-1)/q_i} \bmod n_i$ and $u_i^{q_i} \equiv 1 \pmod{n_i}$ | Fermat condition | two modular exponentiations |
| $(a_i^{(n_i-1)/f} - 1)\cdot w_i \equiv 1 \pmod{n_i}$ for $f \in \{2, q_i\}$ | the gcd condition, via an inverse witness instead of an in-circuit Euclidean loop | big-integer multiplication |
| $q_{i+1} = n_i$ | chain linking | equality |

The base prime is checked by a small lookup table or a deterministic test.

## 3. Tying the certified prime to the Pedersen commitment

The circuit must show that the top value $n_k$ is the value inside the public commitment
$C_a = g^{a} h^{r_a}$.

- Use a commit-and-prove construction (LegoSNARK-style), or commit to the limbs of $n_k$
  with a vector Pedersen commitment and range-check each limb inside the circuit.
- **Size mismatch to plan for:** the current prototype's group order is about 256 bits and its
  range proofs cover 32-bit values. A 1024-bit prime needs either a larger group order
  (more than $2^{1026}$, so that $a+b=2c$ cannot wrap) or limb-wise commitments.
- Mixing a circuit field with the commitment group requires either a curve embedded in the
  SNARK field or a CP-SNARK link. This is the part most likely to need expert review.

## 4. Cost (rough, unmeasured)

The top-level modular exponentiations dominate; each level below costs about half as much.
For 1024-bit primes, expect on the order of $10^7$ constraints, meaning minutes of proving
time on a server, with fast verification. At 128 to 256 bits it is one to two orders of
magnitude cheaper. Benchmark before relying on these numbers.

## 5. Alternatives

- **Miller-Rabin inside the circuit** with Fiat-Shamir bases chosen after committing to $n$.
  Sound against adversarial $n$, but about 40 rounds are needed for roughly $2^{-80}$ error,
  i.e. about 40 full modular exponentiations, far more expensive than the chain above.
- **A public Merkle tree of primes**, workable only for small domains.

## 6. What is still missing

Library selection, a production curve, 1024-bit numbers, and an independent cryptographic review. (The circuit
and the commitment link of section 3 are implemented for 64-bit numbers, see section 7.)

## 7. What is implemented (stark_primality.py)

A hash-based STARK (`stark_core.py`) instead of a pairing SNARK, so there is no trusted setup. Measured on
this container: a proof for a 64-bit prime with a five-tier chain (profile 64, 33, 17, 9, 5; terminal prime 3)
takes about 11 s to produce, 0.1 s to verify and is about 554 KiB; the trace has 824 real rows and 157 columns (the curve commitment adds 253 rows).

- Modular multiplication is a gadget: `A*B = Q*N + V` with `Q` and `V` range-checked to 64 bits by bit
  columns, so no wrap can occur in the 252-bit field. Exponentiation is a square-and-multiply ladder with
  boolean witness bits and an exponent register that is compared with `(n-1)/2`, `2R` or `q`.
- The Bezout witness replaces a gcd loop, exactly as in section 2. `R <= 2q - 1` replaces `R < q` (the chain
  uses `F = 2q`, so `4q^2 > n` is the condition that matters).
- The chain ends at 3, tier links force each `q` to be the next tier's `n`.
- The public input is a curve point `C = n*G + s*H` on the Stark curve (`stark_curve.py`), computed in the circuit
  by double-and-add from a hashed start point; `G` is added only in the last 64 rows so `n` cannot wrap, each
  addition proves its x-coordinates differ, and the bits of `n` are tied to the chain's top value. A scalar
  `n + p` (equal in the field) would commit another value modulo the curve order; it is rejected by a constraint.
- The link to `Ca` is `link_commitments.py` (one integer response below 2^241 across two groups) and
  `goldbach_stark.py` composes everything. Group parameters are also now checked for primality in `zk_primality_circuit.py`.
- Not done: 1024-bit numbers (the 64-bit limbs of section 2 and a larger field), a hiding
  argument beyond random padding and masking, an audit. The size profile (chain length) is public.
