# DO NOT USE: archived, insecure code

Everything in this folder implements the retired "inverse-sum trapdoor" design.

- It leaks both secret primes from public data: `A' + B' = r (mod p)`, then `a = A' * 2c / r`.
  Run `python audit_old_trapdoor.py` in the repo root to reproduce this.
- The C++ version uses 31-bit primes and a non-cryptographic RNG, and never checks its own
  verification values.
- `Quantum_POC_unreliable.md` is pasted assistant output, including leftover chat text and
  physically incorrect claims. It does not describe a working protocol.

These files are kept only so the project history is understandable.
