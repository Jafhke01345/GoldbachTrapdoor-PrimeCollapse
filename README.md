PrimeCollapse (GoldbachTrapdoor): Zero-Knowledge Midpoint Prototype

An educational Zero-Knowledge Range Proof (ZKRP) prototype designed to study verifiable arithmetic over finite fields without external dependencies. The core protocol addresses the statement regarding hidden integers \(a\) and \(b\) where \(a + b = 2c\) and \(0 \le a \le c \le b\) for a public median \(c\).

📊 Component Status Matrix

• Pedersen Commitments + Midpoint Proof (zkrp_toy.py): Fully implemented Schnorr proof of knowledge for \(a + b = 2c\).
• Range Bound Controls (benchmark.py): Fully implemented \([0, 2^{32})\) constraints via bit-decomposition and OR-proofs.
• Recursive Primality Engine (pocklington_chain.py): Fully implemented multi-base recursive Pocklington verifier.
• In-Circuit Primality Spec (zk_primality_circuit.py): Fully implemented mutation-tested relation checker.
• SNARK R1CS Constraint Matrix (PRIMALITY.md): Theoretical circuit gate mapping and architecture documentation.

🚀 Execution & Verification Suite

Run the modules natively using Python 3:
• python benchmark.py (Soundness and range verification loop)
• python pocklington_chain.py --test (Pocklington engine adversarial suite)
• python zk_primality_circuit.py (Circuit relation verifier fuzzing)
• python audit_old_trapdoor.py (Legacy model vulnerability breakdown)

🛠️ Cryptographic Architecture

The system utilizes standard discrete logarithm assumptions:
1. Commitment Phase: Endpoints map to independent generators \(g\) and \(h\) where \(\log_g(h)\) is unknown, publishing \(C_a = g^a \cdot h^{r_a}\) and \(C_b = g^b \cdot h^{r_b}\).
2. Homomorphic Midpoint Check: Validates \(C_a \cdot C_b \cdot g^{-2c} \equiv h^{r_a + r_b} \pmod P\) via a non-interactive Schnorr proof.
3. Integer Range Constraints: Enforces dual range proofs using 1-out-of-2 Sigma OR-proofs to prevent modular wraparounds.
4. Primality Relation Checking: Tracks multi-base Pocklington certificates recursively.

📜 Architectural Evolution & Limitations

The retired legacy design used a multiplicative key trapdoor (\(k = r \cdot (a + b)^{-1} \pmod p\)) which suffered from critical mathematical vulnerabilities where the secret scalar \(r\) leaked via basic addition of public parameters.
Disclaimers: The project employs a 256-bit toy group size, features linear \(\mathcal{O}(N)\) proof scaling, operates in non-constant time, and does not constitute a universal proof of the infinite Goldbach conjecture. It is an educational prototype and should not be used in production.

📄 License

Released under a restrictive Custom Source License.
