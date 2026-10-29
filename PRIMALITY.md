# 🧬 Zero-Knowledge Primality Proofs via Pocklington Chains
To complete the Zero-Knowledge Range Proof (ZKRP) without exposing the secret endpoint values $a$ and $b$, the primitive maps an iterative **Pocklington Primality Certificate** directly into a Non-Interactive Zero-Knowledge (NIZK) circuit witness.

## 1. The Pocklington Criterion
A random 1024-bit prime cannot be verified via standard Pratt certificates due to the hard problem of factoring $n-1$. Instead, we implement Pocklington’s Criterion, requiring only a partial factor $F > \\sqrt{n}$ to be fully isolated:

Let $n = F \\cdot R + 1$ with $F > \\sqrt{n}$ where $F$ is fully factored. If there exists a witness base $a$ such that:
1. $a^{n-1} \\equiv 1 \\pmod n$
2. $\\gcd(a^{\\frac{n-1}{f}} - 1, n) = 1$ for every prime factor $f \\mid F$

Then $n$ is provably prime. By recursively building $F = 2 \\cdot q$, where $q$ is a smaller proven prime and $R < q$, the bit-length doubles at each tier ($17 \\rightarrow 33 \\rightarrow 65 \\rightarrow \\dots \\rightarrow 1024$).

[ Base Prime: 17-bit ] ──► Checked via Deterministic Table Lookups
│
▼
[ Level 1 Chain Link ] ──► n_1 = 2 * q_0 * R_1 + 1 (Assert: 4 * q_0^2 > n_1)
│
▼
[ Level k Chain Link ] ──► n_k = 2 * q_(k-1) * R_k + 1 (Top Level n_k == Secret Bound)

## 2. R1CS / Gate Constraint Mapping
When executed inside a SNARK circuit framework (e.g., Groth16 or `circom`), the public inputs are strictly the commitments $C_a, C_b$ and the public median $c$. The Pocklington chain elements ($q_i, R_i, a_i$) are held strictly in the private witness space.

### Per-Level Arithmetic Constraints:
*   **Chain Structure**: Enforce $n_i - 2 \\cdot q_i \\cdot R_i - 1 == 0$. This requires big-integer multiplication constraints.
*   **Factor Strength**: Enforce $R_i < q_i$ via a bit-decomposition range check to validate that $F^2 > n_i$ holds over the integers.
*   **Fermat Condition**: Calculate $u_i = a_i^{\\frac{n_i-1}{q_i}} \\pmod{n_i}$, verifying $u_i^{q_i} \\equiv 1 \\pmod{n_i}$ via standard square-and-multiply gate arrays.
*   **GCD Witness**: Rather than computing an in-circuit Euclidean GCD loop, the prover supplies an auxiliary witness inversion variable $w_i$, asserting:
    $$(a_i^{\\frac{n_i-1}{f}} - 1) \\cdot w_i \\equiv 1 \\pmod{n_i} \\quad \\text{for } f \\in \\{2, q_i\\}$$

## 3. Commitment Layer Unification
To prove that the top-level certified prime $n_k$ is the exact variable encapsulated by the public Pedersen commitment $C_a$, the circuit enforces a strict identity linkage constraint:

*   **Identity Linkage**: Link the big-integer representation limbs of the private prime $n_k$ directly to the homomorphic group exponents of the outer relation, verifying:
    $$C_a == g^{n_k} \\cdot h^{r_a} \\pmod P$$
