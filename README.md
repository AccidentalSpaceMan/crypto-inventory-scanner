# Crypto Inventory Scanner

[![Tests](https://github.com/AccidentalSpaceMan/crypto-inventory-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/AccidentalSpaceMan/crypto-inventory-scanner/actions/workflows/tests.yml)

A Python CLI that scans a codebase, finds every place cryptography is used, and grades each
algorithm **BROKEN / LEGACY / CURRENT**. It also flags what a future quantum computer would break.

Why? The first step in any post-quantum migration is an **inventory**: you can't replace RSA
or fix MD5 until you know where it lives. This tool automates that step for Python code. Next
it will write the result as a **CBOM** (cryptographic bill of materials), a standard
machine-readable list of every algorithm a system uses.

The scanner **reads** code. It never runs it, and it never connects to anything. Only scan code
you own or have permission to scan.

## Setup

No third-party packages are needed to run it, only Python 3.10+. `pytest` is just for the tests.

```bash
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m cryptoinv scan PATH                     # a folder or a single .py file
python -m cryptoinv scan PATH --fail-on broken    # exit code 1 if anything BROKEN is found (for CI)
python -m cryptoinv scan PATH --rules my.json     # grade with your own rules file
python -m cryptoinv scan PATH --no-color          # plain text
```

### Example: scanning my [Crypto Primitive Playground](https://github.com/AccidentalSpaceMan/crypto-primitive-playground)

```text
Crypto inventory: crypto-playground
15 Python file(s) scanned, 75 finding(s)

LEGACY - works today, plan a migration
  Ed25519 (signature)  [quantum-vulnerable]  - 14 places
      why: Excellent classical signature, but Shor's algorithm breaks it.
      fix: Pair it with ML-DSA in a hybrid signature, then move to ML-DSA.
      cryptoplay/keys.py:9    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed255...
      cryptoplay/keys.py:145  return [Ed25519PrivateKey.generate()]
      ...
  X25519 (key-agree)  [quantum-vulnerable]  - 11 places
      ...

CURRENT - fine today
  AES-GCM (ae)  - 11 places
  HKDF (kdf)  - 2 places
      cryptoplay/hybrid.py:58  return HKDF(  [hash: SHA-384]
  ML-DSA (FIPS 204) (signature)  - 11 places
  ML-KEM (FIPS 203) (kem)  - 8 places
  ...

Quantum readiness
  Ed25519: ML-DSA (FIPS 204) is also used (cryptoplay/keys.py, cryptoplay/signatures.py, ...).
    Possibly a hybrid: check that the two are combined.
  X25519: ML-KEM (FIPS 203) is also used (cryptoplay/keys.py, tests/test_hybrid.py). Possibly a
    hybrid: check that the two are combined.

Summary: BROKEN 0 algorithms (0 places) | LEGACY 2 algorithms (25 places), 2 quantum-vulnerable | CURRENT 8 algorithms (50 places)
```

Ed25519 and X25519 are graded LEGACY because Shor's algorithm breaks them. The scanner also
notices that each one has a post-quantum partner (ML-DSA, ML-KEM) in the same codebase, which is
what a hybrid design looks like.

## How grading works

| Grade | Meaning | Examples |
|---|---|---|
| **BROKEN** | Attackable today, so fix now | MD5, SHA-1, DES, RC4, ECB mode, RSA/DSA/DH under 2048 bits, unsalted password hashes, `random` used for secrets, TLS 1.0/1.1, certificate checks turned off |
| **LEGACY** | Works today, but plan a migration | 3DES, CBC mode, RSA-2048/3072, ECDSA, Ed25519, X25519, ECDH, DH, HMAC-SHA1, PBKDF2 under 600,000 iterations |
| **CURRENT** | Fine today | AES, AES-GCM, ChaCha20-Poly1305, SHA-256/384/512, SHA-3, BLAKE2/3, HMAC-SHA-256+, HKDF, scrypt, bcrypt, Argon2id, ML-KEM, ML-DSA, SLH-DSA, `secrets` / `os.urandom` |

**[quantum-vulnerable]** marks public-key algorithms that Shor's algorithm breaks on a large
quantum computer: RSA, DSA, DH, elliptic curves, Ed25519 and X25519. Symmetric crypto and hashes
are only weakened by Grover's algorithm, which roughly halves their strength. That's why
AES-256 and SHA-384 stay CURRENT.

### The rules are data, not code (crypto-agility)

Every grade, explanation, fix and detection pattern lives in
[`cryptoinv/rules.json`](cryptoinv/rules.json). If a new attack weakens an algorithm, change one
line there (or pass `--rules your.json`) and every scan re-grades. No code changes. The loader
checks the file strictly, so a typo in a grade or an unknown algorithm name is reported instead
of silently ignored.

## How detection works

The scanner uses Python's built-in [`ast`](https://docs.python.org/3/library/ast.html) module to
parse each file into a syntax tree (the same first step Python takes before running code), then
walks the tree:

1. **Imports tell it what names mean.** After `import hashlib as h`, `h.md5(...)` is recognized as
   `hashlib.md5`. A local variable that happens to be called `md5` is not a finding.
2. **Calls reveal details.** It reads literal arguments such as `key_size=1024` (RSA under 2048
   bits is BROKEN), `iterations=1000` for PBKDF2, and the hash inside HMAC (`hmac.new(key, msg,
   hashlib.sha1)` is HMAC-SHA1, LEGACY, not SHA-1, BROKEN).
3. **Context matters for `random`.** `random.shuffle(cards)` in a card game is fine, but
   `token = random.choice(...)` is BROKEN. It looks for secret-sounding names (token, key,
   password, otp, session...) in the surrounding variable, function and argument names.
4. **Comments and strings are ignored.** Text that only mentions "md5" isn't usage.

Libraries covered: `hashlib`, `hmac`, `secrets`, `os.urandom`, `random`, `ssl`, `requests`-style
`verify=False`, [`cryptography`](https://cryptography.io) (including ML-KEM and ML-DSA),
PyCryptodome (`Crypto` / `Cryptodome`), `bcrypt`, `argon2-cffi`, `passlib` and `blake3`.

### Limitations

- It's static analysis: values computed at runtime (`key_size=bits`) can't be read, so those
  findings fall back to the algorithm's normal grade.
- The `random`-for-secrets and password-hash checks are name-based heuristics. They can miss
  cases or occasionally flag harmless code.
- Python only, for now.

## Tests

```bash
python -m pytest
```

The sample files in [`tests/samples/`](tests/samples) contain known weak and strong crypto. Each
line ends with an `# expect: ...` comment naming what the scanner must find there, and the tests
check the scanner finds exactly that: nothing missed, nothing extra. CI runs the suite on
Python 3.10 to 3.14 (Linux) and Windows.

## Roadmap

- [x] Python scanning, grading and terminal report
- [ ] `--cbom out.json`: CycloneDX 1.6 CBOM output
- [ ] More languages (Java, Go, JavaScript) and config files (TLS settings, certificates)
