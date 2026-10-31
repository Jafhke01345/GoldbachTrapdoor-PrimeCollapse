"""
sealed_midpoint.py - the midpoint c published sealed, so two devices holding independent primes a and b
cannot read c (and so cannot derive each other's prime) until BOTH reveal a one-time header.

    device A: prime a, hash chain A          device B: prime b, hash chain B          server: knows c

    setup   each device derives a hash chain from a seed bound to its prime and publishes the END of the
            chain (its anchor, the "premade header"). Session j reveals chain element e_(N-j); anyone checks
            it by hashing forward to the previous header, so headers are one-time and cannot be replayed.
    seal    each device hands the server mask_D = H(label, e) and an operation sel_D = H(label', e) mod 3
            (0 = XOR, 1 = add mod 2^256, 2 = subtract mod 2^256), both derived from its still-secret element.
            The server publishes  S = ((c op_A mask_A) op_B mask_B).
    open    both devices reveal their headers; anyone recovers c by undoing B, then A. The proofs of the
            statement (zkrp_toy.verify) are then checked against that c.
    ratchet after every session the hash label is replaced by H(label, eA, eB), so masks are bound to the
            whole session history and the "hash function" differs from one session to the next.

HONESTY NOTES
    * The operation choice (XOR / add / subtract) is a CLASSICAL stand-in for choosing a measurement basis.
      It has no quantum property, and it adds no strength beyond the pseudorandom mask itself.
    * Secrecy of c against outsiders and against each single device rests on SHA-256 behaving like a random
      oracle. This layer proves nothing about a + b = 2c: correctness comes from zkrp_toy's proofs, checked
      once c is opened. Primality is not covered here (see goldbach_relation.py).
    * The server knows c from the start. After opening, whoever holds a can compute b = 2c - a.
    * Toy, unaudited, not constant-time.

Run `python sealed_midpoint.py` for the adversarial self-test.
"""
import hashlib
import os
import sys
from typing import Optional, Tuple

import zkrp_toy as Z

MOD = 1 << 256
OP_XOR, OP_ADD, OP_SUB = 0, 1, 2


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def _step(i: int, element: bytes) -> bytes:
    """One chain step. The index is part of the input, so each position uses a differently-keyed hash."""
    return _h(b"chain", i.to_bytes(4, "big"), element)


def _apply(sel: int, v: int, m: int) -> int:
    return (v ^ m) if sel == OP_XOR else (v + m) % MOD if sel == OP_ADD else (v - m) % MOD


def _invert(sel: int, v: int, m: int) -> int:
    return (v ^ m) if sel == OP_XOR else (v - m) % MOD if sel == OP_ADD else (v + m) % MOD


def initial_label(anchor_a: bytes, anchor_b: bytes) -> bytes:
    return _h(b"init", anchor_a, anchor_b)


def next_label(label: bytes, ea: bytes, eb: bytes) -> bytes:
    return _h(b"label", label, ea, eb)


def mask_and_op(label: bytes, element: bytes) -> Tuple[int, int]:
    return int.from_bytes(_h(b"mask", label, element), "big"), _h(b"op", label, element)[0] % 3


class HashChain:
    """Hash chain from a seed bound to a private prime. Only the anchor is public."""

    def __init__(self, prime: int, length: int = 32, nonce: Optional[bytes] = None):
        if type(prime) is not int or prime < 2 or type(length) is not int or not (1 <= length <= 100000):
            raise ValueError("bad chain parameters")
        seed = _h(b"seed", prime.to_bytes((prime.bit_length() + 7) // 8, "big"), nonce if nonce is not None else os.urandom(32))
        self._e = [seed]
        for i in range(1, length + 1):
            self._e.append(_step(i, self._e[-1]))
        self.length = length

    @property
    def anchor(self) -> bytes:
        return self._e[self.length]

    def element(self, j: int) -> bytes:
        """The secret element of session j (1-based). Revealing it IS the header for session j."""
        if not (1 <= j <= self.length):
            raise ValueError("session out of range")
        return self._e[self.length - j]


def seal(c: int, mask_a: int, op_a: int, mask_b: int, op_b: int) -> int:
    """Server side: S = ((c op_A mask_A) op_B mask_B) with fixed 256-bit width."""
    if type(c) is not int or not (0 <= c < MOD):
        raise ValueError("c must be a non-negative integer below 2^256")
    return _apply(op_b, _apply(op_a, c, mask_a), mask_b)


class Opener:
    """Anyone's view: tracks both anchors, the next session number and the ratcheted label."""

    def __init__(self, anchor_a: bytes, anchor_b: bytes, length: int):
        if type(anchor_a) is not bytes or type(anchor_b) is not bytes or len(anchor_a) != 32 or len(anchor_b) != 32:
            raise ValueError("anchors must be 32 bytes")
        self.last_a, self.last_b, self.length = anchor_a, anchor_b, length
        self.next_j = 1
        self.label = initial_label(anchor_a, anchor_b)

    def open(self, sealed: int, header_a: bytes, header_b: bytes) -> int:
        """Check both headers for the current session, then unseal. Atomic: nothing advances on failure."""
        if self.next_j > self.length:
            raise ValueError("chain exhausted")
        if type(sealed) is not int or not (0 <= sealed < MOD):
            raise ValueError("bad sealed value")
        for hdr, last in ((header_a, self.last_a), (header_b, self.last_b)):
            if type(hdr) is not bytes or len(hdr) != 32:
                raise ValueError("bad header")
            if _step(self.length - self.next_j + 1, hdr) != last:
                raise ValueError("header does not extend the chain")
        ma, opa = mask_and_op(self.label, header_a)
        mb, opb = mask_and_op(self.label, header_b)
        c = _invert(opa, _invert(opb, sealed, mb), ma)
        self.last_a, self.last_b = header_a, header_b
        self.label = next_label(self.label, header_a, header_b)
        self.next_j += 1
        return c


def open_and_verify(opener: Opener, sealed: int, header_a: bytes, header_b: bytes, pub) -> bool:
    """Unseal c with both headers, then require the public transcript to be a valid proof for exactly it."""
    try:
        c = opener.open(sealed, header_a, header_b)
        return type(pub) is dict and pub.get("c") == c and Z.verify(pub)
    except Exception:
        return False


# ============================================================================ self-test
def _selftest() -> int:
    failures = []

    def expect(name, got, want=True):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    def raises(fn):
        try:
            fn()
            return False
        except ValueError:
            return True

    N = 40
    A, B = HashChain(1000003, N), HashChain(1000033, N)

    def session(j, label, c):
        ma, opa = mask_and_op(label, A.element(j))
        mb, opb = mask_and_op(label, B.element(j))
        return seal(c, ma, opa, mb, opb)

    print("1) honest sessions (30), operation varies, label ratchets")
    op, label = Opener(A.anchor, B.anchor, N), initial_label(A.anchor, B.anchor)
    ops_seen, labels, all_ok = set(), {label}, True
    for j in range(1, 31):
        a, b = 1000003, 1000033 + 2 * (j - 1)
        pub = Z.prove(a, b)                                   # a different midpoint every session
        S = session(j, label, pub["c"])
        ops_seen |= {mask_and_op(label, A.element(j))[1], mask_and_op(label, B.element(j))[1]}
        all_ok &= open_and_verify(op, S, A.element(j), B.element(j), pub)
        label = next_label(label, A.element(j), B.element(j)); labels.add(label)
    expect("all 30 sessions opened and their proofs verified", all_ok)
    expect("all three operations (xor, add, subtract) were used", ops_seen, {0, 1, 2})
    expect("the label was different in every session", len(labels), 31)

    print("\n2) neither device alone can read c")
    label = initial_label(A.anchor, B.anchor)
    c0 = 1000018
    S = session(1, label, c0)
    wrong = _invert(mask_and_op(label, A.element(1))[1], _invert(0, S, 12345), mask_and_op(label, A.element(1))[0])
    expect("device A unseals with a guessed mask for B: wrong c", wrong != c0)
    o = Opener(A.anchor, B.anchor, N)
    expect("device A's header with a forged header for B is refused", raises(lambda: o.open(S, A.element(1), os.urandom(32))))
    expect("S itself does not reveal c (S != c)", S != c0)

    print("\n3) header attacks")
    o = Opener(A.anchor, B.anchor, N)
    expect("headers swapped between devices", raises(lambda: o.open(S, B.element(1), A.element(1))))
    expect("tampered header (one bit)", raises(lambda: o.open(S, bytes([A.element(1)[0] ^ 1]) + A.element(1)[1:], B.element(1))))
    expect("wrong length / wrong type", raises(lambda: o.open(S, b"short", B.element(1))) and raises(lambda: o.open(S, "x" * 32, B.element(1))))
    expect("session skipped (header for session 2 first)", raises(lambda: o.open(S, A.element(2), B.element(2))))
    expect("state unchanged after the failures: session 1 still opens", o.open(S, A.element(1), B.element(1)) == c0)
    expect("replay: the same headers cannot be used twice", raises(lambda: o.open(S, A.element(1), B.element(1))))
    expect("seed element of a different chain", raises(lambda: Opener(HashChain(7, N).anchor, B.anchor, N).open(S, A.element(1), B.element(1))))

    print("\n4) sealed value and proof binding")
    pub = Z.prove(1000003, 1000033)
    label = initial_label(A.anchor, B.anchor)
    S = session(1, label, pub["c"])
    expect("honest open_and_verify", open_and_verify(Opener(A.anchor, B.anchor, N), S, A.element(1), B.element(1), pub))
    expect("sealed value tampered", open_and_verify(Opener(A.anchor, B.anchor, N), (S + 1) % MOD, A.element(1), B.element(1), pub), False)
    expect("proof for a different c", open_and_verify(Opener(A.anchor, B.anchor, N), S, A.element(1), B.element(1), Z.prove(5, 7)), False)
    expect("tampered proof (z)", open_and_verify(Opener(A.anchor, B.anchor, N), S, A.element(1), B.element(1), dict(pub, z=(pub["z"] + 1) % Z.Q)), False)

    print("\n5) arithmetic and ratchet properties")
    for sel in (0, 1, 2):
        edge = all(_invert(sel, _apply(sel, v, m), m) == v for v in (0, 1, MOD - 1, 2 ** 255) for m in (0, 1, MOD - 1, 2 ** 255))
        expect(f"operation {sel} inverts exactly, including wrap-around at 0 and 2^256 - 1", edge)
    expect("the chain hash is position-bound: the same input hashes differently at different positions", _step(1, b"x" * 32) != _step(2, b"x" * 32))
    e = A.element(1)
    expect("same chain element, different label: different mask", mask_and_op(b"label-1", e)[0] != mask_and_op(b"label-2", e)[0])
    expect("order matters: undoing in the wrong order gives the wrong c",
           _invert(1, _invert(2, seal(c0, 11, 1, 5, 2), 11), 5) != c0)
    expect("bad inputs refused", raises(lambda: seal(-1, 0, 0, 0, 0)) and raises(lambda: HashChain(-5)) and raises(lambda: A.element(0)))
    expect("chain exhaustion refused", raises(lambda: _exhaust()))

    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + ', '.join(failures)}")
    print("Reminder: the XOR/add/subtract choice is a classical stand-in, not a quantum property. Toy, unaudited.")
    return 1 if failures else 0


def _exhaust():
    a, b = HashChain(1000003, 2), HashChain(1000033, 2)
    o = Opener(a.anchor, b.anchor, 2)
    label = initial_label(a.anchor, b.anchor)
    for j in (1, 2):
        ma, opa = mask_and_op(label, a.element(j)); mb, opb = mask_and_op(label, b.element(j))
        o.open(seal(5, ma, opa, mb, opb), a.element(j), b.element(j))
        label = next_label(label, a.element(j), b.element(j))
    o.open(0, a.element(1), b.element(1))


if __name__ == "__main__":
    sys.exit(_selftest())
