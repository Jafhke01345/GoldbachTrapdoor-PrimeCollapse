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
| Sealed midpoint: `c` published masked by two devices' one-time hash-chain headers, opened only when both reveal | `sealed_midpoint.py` | Implemented, adversarial self-test; controls who can read `c`, proves nothing about the relation |
| Zero-knowledge proof that a graph is 3-colorable (hex SHA-256 commitments, Fiat-Shamir) | `three_coloring_zk.py` | Implemented, adversarial self-test; standalone, does not strengthen the other components |
| Zero-knowledge proof that a hidden number below 8 is prime, via a graph built from the formula "x is prime" and the 3-coloring proof | `zk_threecolor.py` | Implemented as a demo of the mechanism; tiny numbers only, uses SHA-256 colour commitments and is not linked to the Pedersen commitments |
| The same prime proof linked to a Pedersen commitment `Ca`: colours are Pedersen commitments and a shared-response Schnorr proof ties each bit of `Ca` to the colour of its variable node | `threecolor_link.py` | Implemented, adversarial self-test with removal checks; 3-bit numbers only, about 900 rounds, slow, toy group |
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
python sealed_midpoint.py           # sealed midpoint: hash-chain headers, rotating xor/add/subtract masks
python three_coloring_zk.py         # zero-knowledge graph 3-coloring proof
python zk_threecolor.py             # small-prime proof through 3-coloring (about 25 s)
python threecolor_link.py           # the same proof linked to a Pedersen commitment (about 80 s)
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
| 32-bit | Python (`zkrp_toy.py`) | about 28 ms | about 36 ms | about 14 KiB |
| 32-bit | C, `-O3 -march=native` | about 1 to 1.7 ms | about 3.3 ms | |
| 128-bit | Python | about 106 ms | about 139 ms | about 56 KiB |
| 128-bit | C, `-DNB=128` | about 4.4 ms | about 8.6 ms | |

That is roughly 16 to 24x for proving and 11 to 16x for verifying. Verification became slower when the strict
encoding checks were added (every group element in a transcript gets a subgroup test). Timings on this
shared machine vary noticeably from run to run, so treat the ratios as indicative only. Proof size grows
linearly with the bit range.

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

## Strict encodings

Both verifiers accept exactly one encoding of each proof. Scalars must be canonical integers in `[0, Q)`, so
`e + Q` or `z + Q` (the same value, different bytes) is rejected. Every group element in a transcript must
also be a canonical integer in `(0, P)` and lie in the prime-order subgroup, tested with a Jacobi symbol
(`P = 2Q + 1` is a safe prime, so the subgroup is exactly the quadratic residues). Without that check, a
transcript whose commitments are negated (multiplied by -1, an element of order 2 outside the subgroup)
verifies, because the signs cancel in `Ca * Cb`. `forgery_tools.py` builds such transcripts, and
`benchmark.py` and `test_fast.py` check that both implementations reject them.

## Statement binding

Every bit proof's Fiat-Shamir challenge hashes a tag of the whole statement: the range width, `c`, `Ca` and
`Cb`. A range proof therefore cannot be lifted out of one statement and attached to another that happens to
reuse the same `Ca`. `forgery_tools.transplant_transcript` builds that attack; `benchmark.py` and
`test_fast.py` check that both implementations reject it. Removal checks showed that dropping `c` or `Cb`
from the tag is caught by the tests. Dropping `Ca` or the width is not caught, and those two are
believed redundant: `Ca` is already bound by the bit-commitment recombination, and the width by the proof
length. The tag is cheap, so it stays.

## Sealed midpoint

`sealed_midpoint.py` lets two devices that each hold a prime keep the midpoint `c` unreadable until both
reveal a one-time header. Each device publishes the end of a hash chain bound to its prime. For each
session the server publishes `c` masked with a value derived from each device's next chain element, using
XOR, addition or subtraction mod 2^256 as chosen pseudorandomly per session. The hash label ratchets after
every session.
Neither device alone can unseal `c`. The layer only controls who can read `c`: correctness of
`a + b = 2c` still comes from the proofs, and the server knows `c` from the start. After opening, whoever
holds `a` can compute `b = 2c - a`.

## Graph 3-coloring proof

`three_coloring_zk.py` is the classic Goldreich-Micali-Wigderson zero-knowledge proof that a public graph
has a proper 3-coloring, made non-interactive with Fiat-Shamir. Each round permutes the colors, commits to
every node with a hex SHA-256 commitment, and opens only the two endpoints of one challenged edge; enough
rounds are generated for about 2^-40 soundness error. It is a standalone teaching component: it is not
connected to the other proofs and does not make them stronger. Reducing primality to a coloring instance
would be far too large to be practical, so it does not hide the primes either.

## Linking the prime proof to a commitment

`zk_threecolor.py` alone proves that *some* hidden number below 8 is prime, but nothing ties that number to a
Pedersen commitment. `threecolor_link.py` closes that gap for `Ca = g^a h^ra`. The bit commitments `B_i`
recombine to `Ca` and each is proved to hide 0 or 1 with the same OR proof as the range proof. Every round
also commits to the node colours with Pedersen commitments `K_v`, and for each bit a two-base Schnorr proof
with ONE shared response shows that `B_i` and the colour commitment of that bit's variable node hide the
same bit. The Fiat-Shamir hash covers the graph, `Ca`, every `B_i`, every `K` and every first message.
So `Ca` hides a number that has a proper 3-coloring of the "x is prime" graph, which exists only for primes.
The tests include a split cheater who uses different bits on the two sides (only the shared response
exposes it), colourings with violated edges, transplanted proofs and every-field mutations. Cost is about 900
rounds for 3 bits, which is why real systems use SNARKs. Zero knowledge is argued (simulation under
Fiat-Shamir) and tested statistically, not machine-checked.

Removal checks: deleting either Schnorr equation, the bit-recombination check, the edge-opening check, the
distinct-colours check, the minimum round count, or any one of K, A, Ca, B from the hash input makes the
self-test fail. Two removals are not caught and are judged redundant: comparing `proof["Ca"]` with the
argument (the verifier never uses the copy), and the subgroup check on commitments of nodes that are
neither opened nor part of a bit link (any attempt to open such a node fails anyway).

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
