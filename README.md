# PrimeCollapse

PrimeCollapse is a specialized cryptographic package designed for the efficient representation and validation of large primes through nested Pocklington chains. It provides an alternative to traditional primality proofs by collapsing certificates into compact, verifiable forms.

## Features

- **Compact Primality Certificates**: Implements hierarchical proof structures that reduce the storage overhead of Large Primality Proofs.
- **Pocklington Chain Verification**: Fast validation of primes $p$ where $p-1$ has a partially factored form.
- **Trapdoor Integration**: Optimized for use in Goldbach Trapdoor primitives and related zero-knowledge constructions.

## Installation

```bash
pip install primecollapse
```

## Quick Start

```python
from primecollapse import PrimeCollapse

# Generate a certificate for a large prime
pc = PrimeCollapse()
cert = pc.generate_certificate(p)

# Verify the certificate efficiently
is_valid = pc.verify(cert)
print(f"Valid: {is_valid}")
```

## License

This project is licensed under the MIT License.
