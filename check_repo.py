#!/usr/bin/env python3
"""
check_repo.py - repository guard. Fast structural checks that catch the failures a green
unit-test run can hide:

  * a module silently overwritten by a copy of another (the 'force override' regression)
  * a module whose public API disappeared (tests that only test the wrong file still pass)
  * README text that names files that do not exist, or reverts to retired overclaims
  * binaries, secrets and caches tracked by git

Run from the repository root:   python check_repo.py
Exit code 0 only if every check passes. Used by CI and by the repair script.
"""
import ast
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

REQUIRED = [
    "README.md", "LICENSE", "PRIMALITY.md", ".gitignore",
    "zkrp_toy.py", "benchmark.py", "audit_old_trapdoor.py",
    "pocklington_chain.py", "zk_primality_circuit.py",
    "zkrp_fast.c", "test_fast.py", "check_repo.py",
]

# module -> names that must be defined at top level (its public API)
API = {
    "pocklington_chain.py": {"PrimeCertificate", "build_certificate", "verify_certificate", "run_self_tests"},
    "zk_primality_circuit.py": {"Step", "verify", "build_certificate", "make_params", "commit"},
    "zkrp_toy.py": {"prove", "verify", "commit", "range_prove", "range_verify"},
}

# phrases the README must never regress to (retired overclaims)
BANNED_README = [
    "100% anonymized", "completely blind", "completely blinding", "production-ready",
    "MIT License", "pip install", "unconditionally secure", "provably secure",
]
REQUIRED_README_WORDS = ["toy", "unaudited"]

failures = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if (detail and not ok) else ''}")
    if not ok:
        failures.append(name)


def read(path):
    with open(os.path.join(ROOT, path), "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def top_level_names(path):
    tree = ast.parse(read(path).decode("utf-8"))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.split("\n") if out.returncode == 0 else None


def main():
    print("1) required files")
    for f in REQUIRED:
        check(f"{f} exists", os.path.isfile(os.path.join(ROOT, f)))

    print("\n2) python files compile")
    for f in sorted(x for x in os.listdir(ROOT) if x.endswith(".py")):
        try:
            compile(read(f), f, "exec")
            check(f"{f} compiles", True)
        except (SyntaxError, ValueError) as exc:
            check(f"{f} compiles", False, str(exc)[:80])

    print("\n3) public API of each module")
    for f, need in API.items():
        if not os.path.isfile(os.path.join(ROOT, f)):
            continue
        have = top_level_names(f)
        missing = sorted(need - have)
        check(f"{f} defines {', '.join(sorted(need))}", not missing, f"missing: {missing}")

    print("\n4) modules are not copies of each other")
    pys = [f for f in sorted(os.listdir(ROOT)) if f.endswith(".py")]
    dup = []
    for i, a in enumerate(pys):
        for b in pys[i + 1:]:
            sa, sb = read(a), read(b)
            if len(sa) > 500 and (sa == sb or _near_duplicate(sa, sb)):
                dup.append((a, b))
    check("no two modules are (near-)duplicates", not dup, f"duplicates: {dup}")
    for f in ("pocklington_chain.py", "zk_primality_circuit.py"):
        if os.path.isfile(os.path.join(ROOT, f)):
            first = read(f).decode("utf-8", "replace").lstrip().split("\n")[1:4]
            doc_names = [n for n in ("pocklington_chain", "zk_primality_circuit") if any(n in line for line in first)]
            own = f[:-3]
            check(f"{f} docstring names itself", own in doc_names or not doc_names, f"docstring header mentions {doc_names}")

    print("\n5) git hygiene")
    files = tracked_files()
    if files is None:
        print("  [SKIP] not a git checkout")
    else:
        bad = [f for f in files if f and (f == ".env" or f.endswith((".exe", ".o", ".obj", ".pyc")) or "__pycache__" in f
                                          or os.path.basename(f) in ("zkrp_fast", "zkrp_fast_san"))]
        check("no secrets, binaries or caches tracked", not bad, f"tracked: {bad}")

    print("\n6) README honesty")
    readme = read("README.md").decode("utf-8", "replace")
    low = readme.lower()
    for phrase in BANNED_README:
        check(f"README does not contain '{phrase}'", phrase.lower() not in low)
    for word in REQUIRED_README_WORDS:
        check(f"README states the '{word}' limitation", word in low)
    refs = set(re.findall(r"(?<![\w/.-])([\w][\w./-]*\.(?:py|c|md|yml|ps1))\b", readme))
    missing = sorted(r for r in refs if not os.path.exists(os.path.join(ROOT, r)))
    check("every file named in the README exists", not missing, f"missing: {missing}")
    for f in ("zkrp_fast.c", "test_fast.py", "pocklington_chain.py", "zk_primality_circuit.py"):
        check(f"README mentions {f}", f in readme)

    print(f"\n{'REPO GUARD PASSED' if not failures else str(len(failures)) + ' GUARD CHECK(S) FAILED: ' + '; '.join(failures)}")
    return 1 if failures else 0


def _near_duplicate(a: bytes, b: bytes) -> bool:
    """True when two files differ by under 1% of their lines (a copy with a stray edit)."""
    la, lb = a.split(b"\n"), b.split(b"\n")
    if abs(len(la) - len(lb)) > 3:
        return False
    same = sum(1 for x, y in zip(la, lb) if x == y)
    return same >= 0.99 * max(len(la), len(lb))


if __name__ == "__main__":
    sys.exit(main())
