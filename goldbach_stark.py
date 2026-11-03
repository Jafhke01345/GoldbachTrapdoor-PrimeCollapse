"""
goldbach_stark.py - the whole statement of the repository in zero knowledge, with nothing about the primes opened:

    c is public. The prover knows a and b with   a + b = 2c,   0 <= a <= c <= b   (over the integers, below 2^64),
    and both a and b are PRIME.

Four pieces, each already tested on its own, composed here:
    1. zkrp_toy.py             Pedersen commitments Ca, Cb, the Schnorr midpoint proof and the range proofs
                               (a, c - a in [0, 2^64), so a <= c <= b exactly, not modulo a group order)
    2. stark_primality.py      a STARK that the number inside a curve commitment C = n*G + s*H is prime
    3. link_commitments.py     a sigma protocol that Ca (repository group) and C (Stark curve) hide the SAME integer
    4. this file               prove / verify for the pair of endpoints

What the verifier learns: c, hence a + b; the size profile of each endpoint's certificate chain (public by
construction, see stark_primality.py). Not a, not b, not the factorisation chain, not any blinding value.

Limits: toy groups (fixed, derived from a public seed, so proofs verify across processes), the primality part covers numbers with a five-tier Pocklington chain
(the 64-bit profile, not every prime), the STARK's zero knowledge is argued not proven, unaudited, slow (about 25 s to
prove, under a second to verify, around 1.2 MB).

Run `python goldbach_stark.py` for the end-to-end adversarial self-test (a few minutes).
"""
import copy
import random
import secrets
import sys
import time

import link_commitments as LK
import stark_core as S
import stark_primality as SP
import zkrp_toy as Z

RANGE_BITS = 64


class _Range:
    """Set the range proofs to 64 bits for the duration of a call (the Python reference supports it)."""

    def __enter__(self):
        self.old = Z.N_BITS
        Z.set_range_bits(RANGE_BITS)

    def __exit__(self, *exc):
        Z.N_BITS = self.old


def prove(chain_a, chain_b, profile=SP.PROFILE, _force=False):
    """chain_a / chain_b: certified chains (see stark_primality.make_chain). Returns the public proof object."""
    a, b = chain_a[0]["n"], chain_b[0]["n"]
    if a > b:
        a, b, chain_a, chain_b = b, a, chain_b, chain_a
    w = {}
    with _Range():
        mid = Z.prove(a, b, _witness=w)
    parts = []
    for value, r, chain, Cx in ((a, w["ra"], chain_a, mid["Ca"]), (b, w["rb"], chain_b, mid["Cb"])):
        s = secrets.randbits(SP.EC_BITS)
        C, stark = SP.prove_prime(chain, s, profile, _force=_force)
        Ca_, C_, link = LK.prove(value, r, s)
        assert Ca_ == Cx and C_ == C
        parts.append({"C": C, "link": link, "stark": stark})
    return {"mid": mid, "a": parts[0], "b": parts[1]}


def verify(pub, profile=SP.PROFILE):
    """Total function: anything malformed gives False."""
    try:
        return _verify(pub, profile)
    except Exception:
        return False


def _verify(pub, profile):
    if type(pub) is not dict or set(pub) != {"mid", "a", "b"}:
        return False
    with _Range():
        if not Z.verify(pub["mid"]):
            return False
    for key, Cx in (("a", pub["mid"]["Ca"]), ("b", pub["mid"]["Cb"])):
        part = pub[key]
        if type(part) is not dict or set(part) != {"C", "link", "stark"}:
            return False
        if not LK.verify(Cx, part["C"], part["link"]):
            return False
        if not SP.verify_prime(part["C"], part["stark"], profile):
            return False
    return True


def size_bytes(pub):
    return (Z.proof_size_bytes(pub["mid"]) + sum(S.proof_size_bytes(pub[k]["stark"]) + 5 * 32 + 64 for k in ("a", "b")))


# ============================================================================ self-test
def _selftest():
    failures = []

    def check(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}", flush=True)
        if not ok:
            failures.append(name)

    rng = random.Random(secrets.randbits(64))
    chain_a, chain_b = SP.make_chain(rng=rng), SP.make_chain(rng=rng)
    a, b = sorted((chain_a[0]["n"], chain_b[0]["n"]))
    c = (a + b) // 2
    print(f"a = {a} ({a.bit_length()} bits), b = {b} ({b.bit_length()} bits), c = {c}")

    print("\n1) honest end-to-end proof")
    t0 = time.time()
    pub = prove(chain_a, chain_b)
    t_prove = time.time() - t0
    t0 = time.time()
    ok = verify(pub)
    t_ver = time.time() - t0
    check("honest proof accepted", ok)
    print(f"    prove {t_prove:.1f} s, verify {t_ver:.2f} s, size about {size_bytes(pub) / 1024:.0f} KiB")
    check("the verifier is given c and it is the midpoint", pub["mid"]["c"] == c)
    import os, pickle, subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "proof.pkl")
        with open(path, "wb") as fh:
            pickle.dump(pub, fh)
        code = "import pickle,sys,goldbach_stark as g; sys.exit(0 if g.verify(pickle.load(open(sys.argv[1],'rb'))) else 1)"
        r = subprocess.run([sys.executable, "-c", code, path], cwd=os.path.dirname(os.path.abspath(__file__)))
    check("the proof verifies in a FRESH process (the group is fixed)", r.returncode == 0)
    blob = repr(pub).encode()
    check("neither a nor b appears anywhere in the proof (c = (a + b) / 2 is public by design)",
          str(a).encode() not in blob and str(b).encode() not in blob)

    print("\n2) each piece is load-bearing: break one, the whole proof must fail")
    bad = copy.deepcopy(pub)
    bad["mid"]["c"] += 1
    check("midpoint claim changed (c + 1): rejected", verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["a"], bad["b"] = bad["b"], bad["a"]
    check("the endpoint parts swapped (each is bound to its own commitment): rejected", verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["a"]["C"], bad["a"]["stark"] = bad["b"]["C"], bad["b"]["stark"]
    check("a's link kept but the primality proof of b's number presented for a: rejected (the link catches it)",
          verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["a"]["link"]["z"] += 1
    check("link response changed: rejected", verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["b"]["stark"]["final"][0] = (bad["b"]["stark"]["final"][0] + 1) % S.P
    check("primality proof of b changed: rejected", verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["mid"]["rp_a"] = bad["mid"]["rp_x"]
    check("range proof replaced: rejected", verify(bad), False)
    check("None and {} rejected", (verify(None), verify({})), (False, False))
    bad = copy.deepcopy(pub)
    bad["extra"] = 1
    check("unknown top-level key: rejected", verify(bad), False)
    bad = copy.deepcopy(pub)
    bad["a"]["extra"] = 1
    check("unknown key inside an endpoint part: rejected", verify(bad), False)

    print("\n3) a composite endpoint cannot be proven")
    ch = copy.deepcopy(chain_b)
    q0 = ch[0]["q"]
    while True:
        R0 = rng.randrange(max(1, ch[0]["R"] // 2), ch[0]["R"] + 1)
        n_c = 2 * q0 * R0 + 1
        if not SP.is_prime(n_c) and n_c < (1 << 64):
            break
    ch[0] = {"n": n_c, "q": q0, "R": R0}
    try:
        prove(chain_a, ch)
        check("the honest prover refuses a composite endpoint", False)
    except S.ProverError:
        check("the honest prover refuses a composite endpoint", True)
    forced = prove(chain_a, ch, _force=True)
    check("a forced proof with a composite endpoint is rejected", verify(forced), False)

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: toy groups, soundness conjectured, zero knowledge argued, unaudited.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_selftest())
