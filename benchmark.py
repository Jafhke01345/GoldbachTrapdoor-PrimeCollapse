"""
benchmark.py - soundness tests + timing for zkrp_toy.py.

Part 1 checks that the verifier ACCEPTS honest proofs and REJECTS every cheating attempt
(a benchmark that only runs honest cases can't tell a sound verifier from a broken one).
Part 2 times 10 honest prove/verify cycles on random inputs.

Exit code is 0 only if every soundness test behaves as expected.
"""
import copy
import secrets
import sys
import time

import zkrp_toy as Z


def tamper_tuple(proof, index):
    lst = list(proof)
    lst[index] = (lst[index] + 1) % Z.Q
    return tuple(lst)


def soundness_tests():
    """Each entry: (description, expected verifier result, function returning actual result)."""
    base = Z.prove(1009, 2003)

    def tampered(mutator):
        pub = copy.deepcopy(base)
        mutator(pub)
        return Z.verify(pub)

    def swap_range_proof(pub):
        other = Z.prove(1013, 1999)
        pub["rp_a"] = other["rp_a"]

    def tamper_bit_proof(pub):
        Bs, proofs = pub["rp_x"]
        proofs[5] = tamper_tuple(proofs[5], 4)                         # nudge a z-value

    def tamper_bit_commitment(pub):
        Bs, proofs = pub["rp_a"]
        Bs[3] = Bs[3] * Z.G % Z.P

    return [
        ("honest proof is accepted",                          True,  lambda: Z.verify(base)),
        ("different pair, same c, is accepted",               True,  lambda: Z.verify(Z.prove(1013, 1999))),
        ("wrong public c is rejected",                        False, lambda: Z.verify(base, claimed_c=base["c"] + 1)),
        ("negative a is rejected",                            False, lambda: Z.verify(Z.prove(-3, 1001, _cheat=True))),
        ("a > b (ordering violated) is rejected",             False, lambda: Z.verify(Z.prove(2003, 1009, _cheat=True))),
        ("a above 2^N (wrap-around attempt) is rejected",     False, lambda: Z.verify(Z.prove(2 ** Z.N_BITS + 5, 2 ** Z.N_BITS + 9, _cheat=True))),
        ("tampered commitment Ca is rejected",                False, lambda: tampered(lambda p: p.__setitem__("Ca", p["Ca"] * Z.G % Z.P))),
        ("tampered Schnorr response z is rejected",           False, lambda: tampered(lambda p: p.__setitem__("z", (p["z"] + 1) % Z.Q))),
        ("tampered bit OR-proof is rejected",                 False, lambda: tampered(tamper_bit_proof)),
        ("tampered bit commitment is rejected",               False, lambda: tampered(tamper_bit_commitment)),
        ("range proof from another statement is rejected",    False, lambda: tampered(swap_range_proof)),
    ]


def run_soundness():
    print("=== PART 1: SOUNDNESS TESTS ===")
    failures = 0
    for description, expected, fn in soundness_tests():
        got = fn()
        ok = (got == expected)
        failures += (not ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {description} (verifier returned {got})")
    # the honest prover must also refuse out-of-range input
    try:
        Z.prove(-3, 1001)
        print("  [FAIL] honest prover accepted an out-of-range value")
        failures += 1
    except ValueError:
        print("  [PASS] honest prover refuses out-of-range input")
    return failures


def run_timing(iterations=10):
    print(f"\n=== PART 2: TIMING ({iterations} honest cycles, random inputs) ===")
    print(f"group: {Z.P.bit_length()}-bit safe prime (toy) | range: [0, 2^{Z.N_BITS})")
    prove_t, verify_t, valid_all = [], [], True
    size = 0
    for i in range(iterations):
        a = secrets.randbelow(2 ** (Z.N_BITS - 2))
        b = a + 2 * secrets.randbelow(2 ** (Z.N_BITS - 3))             # keeps a + b even, b >= a
        t0 = time.perf_counter()
        pub = Z.prove(a, b)
        t1 = time.perf_counter()
        ok = Z.verify(pub)
        t2 = time.perf_counter()
        prove_t.append(t1 - t0)
        verify_t.append(t2 - t1)
        valid_all &= ok
        size = Z.proof_size_bytes(pub)
        print(f"  cycle {i + 1:>2}/{iterations}: valid={ok}  prove {t1 - t0:.4f}s  verify {t2 - t1:.4f}s")
    print(f"\n  avg prove  : {sum(prove_t) / iterations:.4f}s")
    print(f"  avg verify : {sum(verify_t) / iterations:.4f}s")
    print(f"  proof size : ~{size / 1024:.1f} KiB (linear in N; Bulletproofs would be logarithmic)")
    return 0 if valid_all else 1


if __name__ == "__main__":
    bad = run_soundness()
    bad += run_timing()
    print("\nRESULT:", "ALL CHECKS PASSED" if bad == 0 else f"{bad} CHECK(S) FAILED")
    print("Reminder: toy parameters, no primality proof, unaudited. See README.md.")
    sys.exit(1 if bad else 0)
