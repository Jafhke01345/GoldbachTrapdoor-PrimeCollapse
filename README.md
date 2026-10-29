# PrimeCollapse (GoldbachTrapdoor): Zero-Knowledge Midpoint Prototype

An elegant, zero-dependency Zero-Knowledge Range Proof (ZKRP) primitive that publicly verifies a mathematical median relationship while completely blinding the underlying prime number pairs.

The core protocol handles the educational statement: "I know hidden integers a and b such that a + b = 2c and 0 <= a <= c <= b, for a public c."

Pure Python, zero external dependencies. Developed as an educational prototype to study discrete-log cryptographic primitives and proof systems.

## 📊 Component Status Matrix

| Component | Implementation File | State / Notes |
| :--- | :--- | :--- |
| Pedersen Commitments + Midpoint Proof | `zkrp_toy.py` | Fully Implemented (Schnorr proof of knowledge for a + b = 2c). |
| Range Bound Controls | `benchmark.py` | Fully Implemented ([0, 2^{32}) constraints via bit-decomposition + OR-proofs). |
| Soundness & Integrity Verification | `benchmark.py` | 10-cycle automated testing loop evaluating tampering and boundaries. |
| Provable Primality Chains | `pocklington_chain.py` | Implemented public Pocklington certificate generator/verifier. |
| In-Circuit Primality SNARK | `PRIMALITY.md` | Theoretical design and arithmetic constraint (R1CS) mapping only. |

## 🚀 Execution & Verification Suite

Run the modules natively with standard Python 3 interpretators:

```bash
# Execute the comprehensive 10-iteration soundness and range testing loop
python benchmark.py

# View the cryptographic breakdown showing the vulnerabilities of the retired model
python audit_old_trapdoor.py

# Generate provable-prime recursive chains and execute artifact tampering tests
python pocklington_chain.py
```

## 🛠️ Cryptographic Architecture

The updated primitive relies on standard, provably secure discrete logarithm assumptions over a prime-order group instead of custom arithmetic tricks:

1. **Commitment Phase:** Endpoints are mapped to independent group generators $g$ and $h$ where $\log_g(h)$ is unknown. Prover publishes $C_a = g^a \cdot h^{r_a}$ and $C_b = g^b \cdot h^{r_b}$ using random blinding scalars.
2. **Homomorphic Midpoint Check:** Utilizing the additive properties of Pedersen commitments, the verifier validates the structural wire balance statement natively: $C_a \cdot C_b \cdot g^{-2c} \equiv h^{r_a + r_b} \pmod P$. The prover supplies a non-interactive Schnorr proof of knowledge (via the Fiat-Shamir transform) demonstrating ownership of the combined scalar $s = r_a + r_b$.
3. **Range Bound Constraints:** To prevent negative number exploits and finite field modular wrapping, the system forces dual range proofs on $a$ and $c - a$. Each bit is independently committed and validated through a 1-out-of-2 Sigma OR-proof. This ensures $a \le c \le b$ holds over the integers rather than wrapping around the field modulus $Q$.

## 📜 Architectural Evolution: The Retired Legacy Design

The repository's previous design utilized a custom multi-precision modular inverse trapdoor where private boundaries were blinded via a multiplicative key: $k = r \cdot (a + b)^{-1} \pmod p$
$$A = a \cdot k, \quad B = b \cdot k$$

### The Mathematical Vulnerability
While mathematically clever, this approach was profoundly broken. Because the blinding operations share a common denominator, an attacker sniffing the public wire data could compute the sum of the coordinates: $A + B \equiv (a + b) \cdot r \cdot (a + b)^{-1} \equiv r \pmod p$

Consequently, the secret scalar $r$ completely leaked via a basic addition of public parameters. Once an attacker extracted $r$, they easily computed its inverse ($r^{-1}$), stripped it from the coordinates, and unblinded the secret boundaries cleanly.

The original files, obsolete scripts, and the unverified native binaries have been entirely stripped from the main profile and archived under the `legacy/` directory for historical analysis only. `audit_old_trapdoor.py` programmatically replicates this exact leakage vector to demonstrate the necessity of shifting to a homomorphic commitment ecosystem.

## ⚠️ Limitations & Disclaimers
- **Toy Group Size:** Employs a 256-bit group for readability and performance execution loops. Real-world applications require migrating to secure curves like Ristretto255.
- **Proof Footprint Scaling:** Proof size scales linearly $\mathcal{O}(N)$ with bit-decomposition. Bulletproofs are required to collapse this bound down to logarithmic $\mathcal{O}(\log N)$ footprints.
- **Non-Constant Time:** This repository is an educational prototype and has not undergone a professional peer review or formal security audit. Do not deploy it in production environments.

## 📄 License
This project is released under a restrictive, proprietary Custom Source License. Review `LICENSE` for the complete declaration parameters.
