"""
audit_old_trapdoor.py - demonstrates WHY the retired "inverse-sum trapdoor" design is insecure.

Old scheme (kept in legacy/): publish c = (a+b)/2, A' = a*k, B' = b*k  (mod p) with
k = r * (a+b)^-1 and a secret scalar r.

Attack, using ONLY public data (c, A', B', p):
    A' + B' = (a+b) * k = r  (mod p)          -> the "secret" r is just the sum of the two wires
    a = A' * 2c * r^-1  (mod p),  b = B' * 2c * r^-1  (mod p)

The earlier "patch" (adding r) defeated only the naive attack a = A' * 2c, which is why a test
that tries just that one attack wrongly reports "secure".

Exit code 0 means the leak was CONFIRMED (this script is a regression demo, not a pass/fail test
of the new protocol).
"""
import math
import secrets
import sys


def is_prime(n, k=30):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(c):
            return c


def old_scheme(a, b, p):
    s = a + b
    while True:
        r = secrets.randbelow(p - 2) + 2
        if math.gcd(r, p) == 1:
            break
    k = r * pow(s, -1, p) % p
    return s // 2, r, a * k % p, b * k % p          # public c, secret r, wires A', B'


def main():
    p = gen_prime(512)
    a, b = gen_prime(256), gen_prime(256)
    c, r, A, B = old_scheme(a, b, p)

    naive = A * 2 * c % p
    print("naive attack  a = A'*2c                 ->", "recovers a" if naive == a else "fails (this is all the old audit tried)")

    r_rec = (A + B) % p
    print("secret r      = (A' + B') mod p         ->", "RECOVERED" if r_rec == r else "not recovered")

    a_rec = A * 2 * c * pow(r_rec, -1, p) % p
    b_rec = B * 2 * c * pow(r_rec, -1, p) % p
    leaked = (a_rec == a and b_rec == b)
    print("a, b          = A'*2c/r, B'*2c/r        ->", "BOTH PRIMES RECOVERED" if leaked else "not recovered")

    # the "ambiguity" argument: a wrong r' is supposed to give an equally valid-looking pair
    fake = secrets.randbelow(p - 2) + 2
    sa, sb = A * pow(fake, -1, p) * 2 * c % p, B * pow(fake, -1, p) * 2 * c % p
    print("balance check with a random wrong r'    ->", (sa + sb) % p == 2 * c % p, "(a wrong r' does NOT balance)")
    print("balance check with r' = A' + B'         ->", (a_rec + b_rec) % p == 2 * c % p, "(the check itself pins down r)")

    print("\nVERDICT:", "old design LEAKS both secret primes from public data." if leaked else "leak not reproduced (unexpected).")
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
