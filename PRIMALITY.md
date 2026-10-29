# Zero-Knowledge Primality via Pocklington Chains (design note)

Status: design document. The repo contains a *public* reference verifier
(`pocklington_chain.py`) and a prototype of the commitment and range-proof layers
(`zkrp_toy.py`). The in-circuit (SNARK) part described below is not implemented, and the
cost figures are rough estimates, not measurements.

## Goal
\ Extend the range proof so that the hidden endpoints $a$ and $b$ are also proven prime,
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
side effect: primes generated this way are not uniformly distributed among all primes of that
size. Do not describe the anonymity set as "uniform".

pocklington_chain.py generates such chains and verifies them (about 9 ms for a 1024-bit
chain in a pure-Python run). The certificate reveals $n$, so on its own it is a
*witness*, not a zero-knowledge proof.

## 2. Mapping the check into a circuit

Inside a SNARK framework (e.g. arkworks, halo2, or `circom`):

- Public inputs: the commitments $C_a$, $C_b$ and the median $c$.
- Private witness: the chain values $(q_i, R_i, a_i)$, the Bezout witnesses $w_i$ below, and the commitment randomness.

Per-level constraints:

| Constraint | Meaning | Cost driver |
|---|---|---|
| $n_i - 2 q_i R_i - 1 = 0$ | chain structure | big-integer multiplication |
| $R_i < q_i$ | guarantees $F^2 > n_i$ | bit-decomposition range check |
| $u_i = a_i^{(n_i-1)/q_i} \pmod{n_i}$ and $u_i^{q_i} \equiv 1 \pmod{n_i}$ | Fermat condition | two modular exponentiations |
| $(a_i^{(n_i-1)/f} - 1)\cdot w_i \equiv 1 \pmod{n_i}$ for $f \in {2, q_i}$ | the gcd condition, via an inverse witness instead of an in-circuit Euclidean loop | big-integer multiplication |
| $q_{i+1} = n_i$ | chain linking | equality |

The base prime is checked by a small lookup table or a deterministic test.

## 3. Tying the certified prime to the Pedersen commitment
The circuit must show that the top value $n_k$ is the value inside the public commitment
$C_a = g^{a} h^{r_a}$.

- Use a commit-and-prove construction (LegoSNARK-style), or commit to the limbs of $n_k$
  with a vector Pedersen commitment and range-check each limb inside the circuit.
- Size mismatch to plan for: the current prototype's group order is about 256 bits and its
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

- Miller-Rabin inside the circuit with Fiat-Shamir bases chosen after committing to $n$.
  Sound against adversarial $n$, but about 40 rounds are needed for roughly $2^{-80}$ error,
  i.e. about 40 full modular exponentiations, far more expensive than the chain above.
- A public Merkle tree of primes, workable only for small domains.

## 6. What is still missing

Library selection, a production curve, an implemented circuit, the commitment link of
section 3, and an independent cryptographic review.
