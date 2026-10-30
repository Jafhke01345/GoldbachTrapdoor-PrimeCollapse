# PrimeCollapse (GoldbachTrapdoor): zero-knowledge midpoint prototype

An educational prototype for this statement, about a public integer `c`:

> "I know hidden integers `a` and `b` with `a + b = 2c` and `0 <= a <= c <= b`."

It is a toy: 256-bit group, unaudited, not constant-time, not for production use.

## Status

| Component | File | State |
|---|---|---|
| Pedersen commitments, Schnorr proof of `a + b = 2c`, bit-decomposition range proofs | `zkrp_toy.py` | Implemented, tested by `benchmark.py` |
| Soundness tests and timing (12 checks, 10 timed cycles) | `benchmark.py` | Implemented |
| Native C implementation of the same protocol | `zkrp_fast.c` | Implemented, cross-checked against `zkrp_toy.py` by `test_fast.py` |
| Recursive Pocklington certificates, one base and one Bezout inverse per prime factor (`a2`/`w2`, `aq`/`wq`) | `pocklington_chain.py` | Implemented, adversarial self-test (`--test`) |
| Pocklington chain checked against a Pedersen commitment, one base per tier (flat step list) | `zk_primality_circuit.py` | Implemented as a relation checker; **not zero-knowledge** |
| Zero-knowledge proof that the endpoints are prime | `PRIMALITY.md` | Design note only, not implemented |
| Repository guard (structure, API, README checks) | `check_repo.py` | Implemented, run by CI |

Known gap: `pocklington_chain.py` and `zk_primality_circuit.py` use different certificate formats
(separate bases per factor versus one base per tier). A certificate from one is not always accepted
by the other, and there is no adapter yet.

Nothing here proves that `a` and `b` are prime in zero knowledge. The range proof hides the endpoints
beyond what `c` implies; the primality code checks certificates in the clear.

## Run it

```bash
python benchmark.py                 # soundness tests, then 10 timed prove/verify cycles
python audit_old_trapdoor.py        # shows why the retired design leaked its secrets
python zk_primality_circuit.py      # circuit relation checker, adversarial self-test
python pocklington_chain.py --test  # Pocklington engine, adversarial self-test
python check_repo.py                # repository guard

# native module (needs GCC or Clang; uses unsigned __int128, so not MSVC)
gcc -O3 -march=native -o zkrp_fast zkrp_fast.c
./zkrp_fast selftest
python test_fast.py . ./zkrp_fast   # differential and forgery tests against zkrp_toy.py
```

On Windows with MinGW-w64, add `-lbcrypt` to the `gcc` line. The native module has only been built
and tested on Linux with GCC 13.

CI (`.github/workflows/ci.yml`) runs all of the above on every push.

## Speed

Measured on one shared 2-vCPU Linux sandbox (2.1 GHz Xeon, Python 3.13, GCC 13), same 256-bit group,
32-bit range, medians over many runs:

| Build | Prove | Verify |
|---|---|---|
| Python (`zkrp_toy.py`) | about 27 ms | about 27 ms |
| C, `-O3 -march=native` | about 1.1 ms | about 1.5 ms |

That is roughly 25x for proving and 18x for verifying. Timings on a shared machine are noisy, so treat
the ratios as the reliable part. Proof size is about 14 KiB and grows linearly with the bit range.

## How the protocol works

1. **Commit:** `Ca = g^a h^ra`, `Cb = g^b h^rb` (Pedersen, perfectly hiding). `log_g(h)` is unknown
   because `g` and `h` are derived by hashing.
2. **Midpoint:** `Ca * Cb * g^(-2c) = h^(ra+rb)` holds exactly when `a + b = 2c`. A Fiat-Shamir Schnorr
   proof shows knowledge of `ra + rb`.
3. **Range:** two bit-decomposition range proofs, one for `a` and one for `c - a`. `a` in range blocks
   negative or wrapped values; `c - a` in range gives `a <= c <= b`. Each bit uses a Schnorr OR-proof.

The verifier learns `c`, and therefore `a + b`. Nothing else about `a` and `b` is revealed beyond what
the statement implies.

## Limitations

- 256-bit toy group, regenerated at every import of `zkrp_toy.py`. Real use needs a standard curve such
  as Ristretto255 and a real range-proof system such as Bulletproofs.
- Range limited to 32 bits. Larger endpoints need a larger group or limb-wise commitments.
- No zero-knowledge primality proof (see `PRIMALITY.md`), and no audit.
- Not constant-time.

## History

The first version published `c`, `A' = a*k`, `B' = b*k` with `k = r * (a+b)^-1 mod p`. It leaked both
primes: `A' + B' = r (mod p)`, so anyone could recover `r` and then `a` and `b`. `audit_old_trapdoor.py`
reproduces the leak, and the retired code is archived under `legacy/` for reference only.

## License

Custom Source License, see `LICENSE`.
