# PrimeCollapse (GoldbachTrapdoor): zero-knowledge midpoint prototype

An educational prototype for this statement:

> "I know hidden integers `a` and `b` with `a + b = 2c` and `0 <= a <= c <= b`, for a public `c`."

Pure Python, no dependencies. **Not production cryptography.** See "Limitations".

## Status

| Piece | State |
|---|---|
| Pedersen commitments + Schnorr proof of `a + b = 2c` | implemented (`zkrp_toy.py`) |
| Range proofs (`a` and `c - a` in `[0, 2^32)`) via bit decomposition + OR-proofs | implemented |
| Soundness tests (negative values, ordering, wrap-around, tampering) | implemented (`benchmark.py`) |
| Public Pocklington certificate generator/verifier | implemented (`pocklington_chain.py`), **not** zero-knowledge |
| Proof that `a` and `b` are prime, in zero knowledge | **design only** (`PRIMALITY.md`) |
| Production group / library, independent review | **not done** |

## Run it

```bash
python benchmark.py             # soundness tests, then 10 timed prove/verify cycles
python audit_old_trapdoor.py    # shows why the retired design leaked its secrets
python pocklington_chain.py     # provable-prime chains and tamper tests
```

`benchmark.py` exits non-zero if any soundness test misbehaves.

## How it works

1. **Commit:** `Ca = g^a h^ra`, `Cb = g^b h^rb` (Pedersen, perfectly hiding).
2. **Midpoint:** `Ca * Cb * g^(-2c) = h^(ra+rb)` holds exactly when `a + b = 2c`. A
   Fiat-Shamir Schnorr proof shows knowledge of `ra + rb`.
3. **Range:** two bit-decomposition range proofs, one for `a` and one for `c - a`.
   `a` in range blocks negative or wrapped values. `c - a` in range gives `a <= c <= b`.

What the verifier learns: `c`, and therefore `a + b`. Nothing else about `a` and `b` is
revealed beyond what the statement itself implies.

## Limitations

- 256-bit toy group (far too small for real use), regenerated at every import.
- Proof size grows linearly with the bit range (about 14 KiB here).
- Values are limited to 32 bits. 1024-bit endpoints would need a larger group or limb-wise commitments.
- Not constant-time and not audited.
- No primality proof yet, so the endpoints are not proven to be prime.

## History: the retired design

The first version published `c`, `A' = a*k`, `B' = b*k` with `k = r * (a+b)^-1`. It was
broken: `A' + B' = r (mod p)`, so anyone could recover the "secret" `r`, and then both
primes, from public data. A later patch added `r` but did not fix this. The old code is kept
under `legacy/` for reference only. `audit_old_trapdoor.py` reproduces the leak.
The earlier "quantum variant" write-up described no real protocol and is also archived.

## License

See `LICENSE`.
