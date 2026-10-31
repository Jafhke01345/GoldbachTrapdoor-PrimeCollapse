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
| Pocklington chain checked against a Pedersen commitment, one base per prime factor (flat step list) | `zk_primality_circuit.py` | Implemented as a relation checker; **not zero-knowledge** |
| Conversion between the engine's nested certificates and the circuit's flat steps, with a differential test of both verifiers | `certificate_adapter.py` | Implemented, tested |
| The whole statement as one checker: Pedersen/range proofs plus a Pocklington certificate for each committed endpoint | `goldbach_relation.py` | Implemented, adversarial self-test; **primes are opened in the clear, not zero-knowledge** |
| Zero-knowledge proof that the endpoints are prime | `PRIMALITY.md` | Design note only, not implemented |
| Repository guard (structure, API, README checks) | `check_repo.py` | Implemented, run by CI |

Both Pocklington modules now use the same certificate structure (a separate base and Bezout inverse
for each of the factors 2 and q). `certificate_adapter.py` converts between the nested engine format and
the flat circuit format, and its self-test checks that both verifiers give the same verdict on honest
certificates and on random single-field mutations. One difference remains: the engine's terminal prime
must be below 2^20, the circuit's below 2^32, so a circuit chain with a larger terminal prime cannot be
converted (the adapter refuses it instead of guessing).

`goldbach_relation.py` ties the pieces together over one shared group: the proofs in `zkrp_toy.py`, the
commitment openings, and a certificate for each endpoint, checked together. It shows what a zero-knowledge
primality proof would have to establish; it does not hide the primes, because the openings are checked in
the clear. At the default 32-bit range the endpoints are small primes; the self-test also runs it at 128 bits.

Nothing here proves that `a` and `b` are prime in zero knowledge. The range proof hides the endpoints
beyond what `c` implies; the primality code checks certificates in the clear.

## Run it

```bash
python benchmark.py                 # soundness tests, then 10 timed prove/verify cycles
python audit_old_trapdoor.py        # shows why the retired design leaked its secrets
python zk_primality_circuit.py      # circuit relation checker, adversarial self-test
python pocklington_chain.py --test  # Pocklington engine, adversarial self-test
python certificate_adapter.py       # format conversion and engine-versus-circuit differential test
python goldbach_relation.py         # combined statement: commitments, range proofs and primality
python check_repo.py                # repository guard

# native module (needs GCC or Clang; uses unsigned __int128, so not MSVC)
gcc -O3 -march=native -o zkrp_fast zkrp_fast.c
./zkrp_fast selftest
python test_fast.py . ./zkrp_fast   # differential and forgery tests against zkrp_toy.py

# the range width is a build option; 128-bit version (Python reference must use the same width)
gcc -O3 -march=native -DNB=128 -o zkrp_fast_wide zkrp_fast.c
ZKRP_NBITS=128 python test_fast.py . ./zkrp_fast_wide
```

On Windows with MinGW-w64, add `-lbcrypt` to the `gcc` line. The native module has only been built
and tested on Linux with GCC 13. It refuses a group too small for its width (`2^(NB+3) < Q` is required).

CI (`.github/workflows/ci.yml`) runs all of the above on every push.

## Speed

Measured on one shared 2-vCPU Linux sandbox (2.1 GHz Xeon, Python 3.13, GCC 13), same 256-bit group,
medians over many runs:

| Range | Build | Prove | Verify | Proof size |
|---|---|---|---|---|
| 32-bit | Python (`zkrp_toy.py`) | about 28 ms | about 28 ms | about 14 KiB |
| 32-bit | C, `-O3 -march=native` | about 1.0 ms | about 1.5 ms | |
| 128-bit | Python | about 112 ms | about 118 ms | about 56 KiB |
| 128-bit | C, `-DNB=128` | about 4.2 ms | about 5.7 ms | |

That is roughly 27x for proving and 19 to 21x for verifying at both widths. Timings on a shared machine are
noisy, so treat the ratios as the reliable part. Proof size grows linearly with the bit range.

## How the protocol works

1. **Commit:** `Ca = g^a h^ra`, `Cb = g^b h^rb` (Pedersen, perfectly hiding). `log_g(h)` is unknown
   because `g` and `h` are derived by hashing.
2. **Midpoint:** `Ca * Cb * g^(-2c) = h^(ra+rb)` holds exactly when `a + b = 2c`. A Fiat-Shamir Schnorr
   proof shows knowledge of `ra + rb`.
3. **Range:** two bit-decomposition range proofs, one for `a` and one for `c - a`. `a` in range blocks
   negative or wrapped values; `c - a` in range gives `a <= c <= b`. Each bit uses a Schnorr OR-proof.

Integer-level guarantee: the proofs bind `c` only modulo the group order Q, so both verifiers also require
`c` to be a plain integer with `0 <= c < 2^(N_BITS+1)`. Then `c = a + x` exactly over the integers (with
`x = c - a`, both below 2^32), `b = a + 2x`, and `a <= c <= b` holds over the integers and not merely mod Q.
Without that check a transcript claiming `c + Q` would verify; `benchmark.py` and `test_fast.py` test it.

The verifier learns `c`, and therefore `a + b`. Nothing else about `a` and `b` is revealed beyond what
the statement implies.

## Limitations

- 256-bit toy group, regenerated at every import of `zkrp_toy.py`. Real use needs a standard curve such
  as Ristretto255 and a real range-proof system such as Bulletproofs.
- Default range is 32 bits. The Python reference can widen it with `zkrp_toy.set_range_bits(n)` up to the toy
  group's no-wrap limit (about 250 bits), and `goldbach_relation.py` tests 128-bit primes with multi-tier
  certificates that way. The C module takes the width as a build option (`-DNB=128`; default 32). Endpoints beyond the
  group size need limb-wise vector commitments.
- No zero-knowledge primality proof (see `PRIMALITY.md`), and no audit.
- Not constant-time.

## History

The first version published `c`, `A' = a*k`, `B' = b*k` with `k = r * (a+b)^-1 mod p`. It leaked both
primes: `A' + B' = r (mod p)`, so anyone could recover `r` and then `a` and `b`. `audit_old_trapdoor.py`
reproduces the leak, and the retired code is archived under `legacy/` for reference only.

## License

Custom Source License, see `LICENSE`.
