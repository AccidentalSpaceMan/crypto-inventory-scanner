# Crypto Inventory Scanner

[![Tests](https://github.com/AccidentalSpaceMan/crypto-inventory-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/AccidentalSpaceMan/crypto-inventory-scanner/actions/workflows/tests.yml)

A Python CLI that scans a codebase, finds every place cryptography is used, and grades each
algorithm **BROKEN / LEGACY / CURRENT**. It also flags what a future quantum computer would break.

Why? The first step in any post-quantum migration is an **inventory**: you can't replace RSA
or fix MD5 until you know where it lives. This tool automates that step for **Python, Java,
JavaScript, TypeScript and Go** code, plus the **certificates and keys** stored alongside it. It can
also write the result as a **CBOM** (cryptographic bill of materials) in the standard
[CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/) format, so other tools can read it.

The scanner **reads** files. It never runs code, never connects to anything, never asks for
passwords and never prints key material. Only scan code you own or have permission to scan.

## Setup

Scanning code needs nothing beyond Python 3.10+. Reading certificate and key files needs the
[`cryptography`](https://cryptography.io) library. Without it, those files are listed as skipped,
with an install hint. `requirements.txt` installs it along with the test tools: `pytest`, the
official CycloneDX library (to validate CBOM output), `jsonschema` (to validate SARIF output) and
`bcrypt` (used by one key test).

```bash
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m cryptoinv scan PATH                     # a folder, or a single source / certificate / key file
python -m cryptoinv scan PATH --cbom out.json     # also write a CycloneDX 1.6 CBOM
python -m cryptoinv scan PATH --sarif out.sarif   # also write SARIF 2.1.0 (GitHub code scanning)
python -m cryptoinv scan PATH --exclude tests     # skip a folder or pattern (repeatable)
python -m cryptoinv scan PATH --fail-on broken    # exit code 1 if anything BROKEN is found (for CI)
python -m cryptoinv scan PATH --rules my.json     # grade with your own rules file
python -m cryptoinv scan PATH --no-color          # plain text
```

### Example: scanning my [Crypto Primitive Playground](https://github.com/AccidentalSpaceMan/crypto-primitive-playground)

```text
Crypto inventory: crypto-playground
15 file(s) scanned (15 Python), 75 finding(s)

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

## GitHub code scanning (SARIF)

An inventory is a snapshot. To catch weak crypto *as it's written*, `--sarif out.sarif` writes the
findings in SARIF 2.1.0, the OASIS standard format for static-analysis results that GitHub,
GitLab, Azure DevOps and many editors understand.

This repository scans itself on every push and pull request with
[`.github/workflows/code-scanning.yml`](.github/workflows/code-scanning.yml), which uploads the
SARIF file to GitHub code scanning:

- **BROKEN** findings become **errors** and **LEGACY** ones **warnings**, in the repository's
  *Security > Code scanning* tab and as annotations on the changed lines of a pull request.
- Each algorithm is a SARIF *rule* whose help text is the why/fix advice. Each rule also gets a
  `security-severity` score (BROKEN 8.0 is High, LEGACY 5.0 is Medium), which GitHub uses for
  its severity labels. Quantum-vulnerable rules are tagged `quantum-vulnerable`.
- CURRENT findings are left out by default, since they're fine. Use
  `--sarif-min-grade current` to include them as notes, or `broken` for errors only.

The workflow file explains how to copy it into another repository you own.

### Excluding files and reviewed lines

- `--exclude PATTERN` skips matching files or folders, relative to the scanned path:
  `--exclude tests`, `--exclude "vendor_*"`, `--exclude "*.min.js"`. It can be repeated. This
  repository's workflow excludes `tests/`, whose sample files contain weak crypto on purpose.
- A line containing **`cryptoinv: ignore`** (in a `#` or `//` comment) is left out of the report,
  the CBOM and the SARIF file. Use it for lines a person has reviewed, ideally with a reason:
  `hashlib.md5(data)  # cryptoinv: ignore (cache key, not security)`. The report always says how
  many findings were left out this way, so nothing disappears silently. The scanner uses it on
  its own key-type checks, which name RSA or Ed25519 only to recognise them.

## CBOM output

An SBOM (software bill of materials) is an ingredients list of the libraries in a piece of
software. A **CBOM** is the same idea for cryptography: every algorithm and protocol, and
everywhere it's used. `--cbom out.json` writes one in
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/), the OWASP standard that added
"cryptographic-asset" components for exactly this purpose.

- Each algorithm becomes one `cryptographic-asset` component with its CycloneDX `primitive`
  (hash, ae, signature, kem, key-agree...) and cipher `mode` where known.
- Quantum-vulnerable algorithms get `nistQuantumSecurityLevel: 0`: no security against a
  quantum computer.
- Every place it was found is an `evidence.occurrences` entry with file, line, the matched
  symbol, and the line of code.
- The grade, why, fix and post-quantum replacement aren't part of the standard, so they're
  stored as `cryptoinv:` properties (CycloneDX's official place for tool-specific data).
- TLS settings become `protocol` assets.

Example: [`examples/crypto-playground-cbom.json`](examples/crypto-playground-cbom.json) is the
CBOM of my playground project. One component from it:

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto:X25519",
  "name": "X25519",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "key-agree", "nistQuantumSecurityLevel": 0 }
  },
  "evidence": {
    "occurrences": [
      { "location": "cryptoplay/hybrid.py", "line": 37,
        "symbol": "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey",
        "additionalContext": "from cryptography.hazmat.primitives.asymmetric.x25519 import ..." }
    ]
  },
  "properties": [
    { "name": "cryptoinv:grade", "value": "LEGACY" },
    { "name": "cryptoinv:quantumVulnerable", "value": "true" },
    { "name": "cryptoinv:postQuantumReplacement", "value": "MLKEM" }
  ]
}
```

The tests validate every generated CBOM against the official CycloneDX 1.6 JSON schema.

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

### Python

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

### Java

Python has no built-in Java parser, so `.java` files are read as text in two steps:

1. **Mask.** Comments, and the inside of every string, are blanked out in a copy of the file.
   Every character keeps its position, so line numbers stay exact. A comment or string that only
   *mentions* `MessageDigest.getInstance("MD5")` can't match.
2. **Match.** Java's crypto API names algorithms as strings, so the scanner finds calls like
   `Cipher.getInstance(...)`, `MessageDigest`, `Mac`, `Signature`, `KeyPairGenerator`,
   `KeyAgreement`, `SecretKeyFactory`, `SSLContext` and `KEM`, then reads the real string and
   looks it up in the `java` section of `rules.json`.

What it understands:

- **Cipher transformations:** `"AES/CBC/PKCS5Padding"` is AES + CBC. `"AES/GCM/NoPadding"` is
  AES-GCM. A bare `"AES"` is flagged as **ECB**, because that's what Java silently uses when no
  mode is given.
- **Compound names:** `"SHA1withRSA"` is SHA-1 (BROKEN) + RSA. `"PBEWithMD5AndDES"` is MD5 + DES.
- **Across lines:** `kpg = KeyPairGenerator.getInstance("RSA")` then `kpg.initialize(1024)`
  gives RSA under 2048 bits. `new PBEKeySpec(pw, salt, 1000, 256)` sets the PBKDF2 grade.
  Constants like `static final String ALG = "DES"` are resolved.
- **Insecure randomness:** `new Random()`, `Math.random()`, `ThreadLocalRandom` and
  `RandomStringUtils` used in a secret-sounding context (`generateToken()`, `apiKey = ...`).
- **TLS:** old protocol versions in `SSLContext.getInstance` / `setEnabledProtocols`, trust-all
  `checkServerTrusted() {}` managers, and hostname verifiers that always return `true`.
- **Libraries:** the JDK (including ML-KEM / ML-DSA), Apache Commons `DigestUtils`, Guava
  `Hashing`, and Bouncy Castle's ML-KEM / ML-DSA / SLH-DSA parameter specs.

### JavaScript and TypeScript

`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts` and `.tsx` files use the same mask-then-match
approach as Java. The masking also understands backtick `` `template strings` `` and regex
literals (`/"md5"/`), telling a regex apart from division (`a / 2`). Minified bundles (`.min.js`),
type declarations (`.d.ts`) and `node_modules/` are skipped.

What it understands:

- **Node's `crypto` module**, however it's imported (`require('crypto')`,
  `import * as c from 'node:crypto'`, `const { createHash: h } = require('crypto')`, or the
  usual name `crypto`): `createHash('md5')`, `createHmac('sha1', key)` (HMAC-SHA1),
  `createCipheriv('aes-128-ecb', ...)`, `createSign('RSA-SHA1')`, `pbkdf2Sync(pw, salt, 1000, ...)`,
  `scryptSync`, `randomBytes`, `getDiffieHellman('modp2')` (a 1024-bit group, so BROKEN) and
  `generateKeyPairSync('rsa', { modulusLength: 1024 })` (RSA under 2048 bits), including ML-KEM
  and ML-DSA key types.
- **OpenSSL cipher names:** `"aes-256-gcm"` is AES-GCM. A name with no mode gets OpenSSL's
  default, shown in the details: `"aes256"` means AES-256-**CBC**, but `"des-ede3"` means 3DES
  in **ECB**.
- **WebCrypto** (browsers, Deno, Node): algorithm objects like `{ name: 'AES-GCM' }`,
  `{ name: 'RSA-OAEP', modulusLength: 1024 }` and
  `{ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000 }`, plus string arguments such as
  `subtle.digest('SHA-1', data)`.
- **JSON Web Tokens** (`jsonwebtoken`): the `algorithm` / `algorithms` option of `jwt.sign` and
  `jwt.verify`. **`'none'` is BROKEN**, because an unsigned token can be forged by anyone.
- **Libraries:** `crypto-js` (`CryptoJS.MD5`, `CryptoJS.DES`, `CryptoJS.mode.ECB`, and imports
  like `crypto-js/md5`), `bcrypt` / `bcryptjs` and `argon2`.
- **Passwords and randomness:** `createHash('sha256').update(password)` is flagged as an unsalted
  password hash. `Math.random()` is flagged when it's making a token, key, session ID or similar.
- **TLS:** `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = '0'`, no-op
  `checkServerIdentity`, and old versions in `minVersion` / `maxVersion` / `secureProtocol`.

### Go

Go keeps its crypto in packages imported by path (`"crypto/md5"`, `"golang.org/x/crypto/bcrypt"`),
which makes it the most straightforward language to scan. `.go` files are masked like Java (Go's
backtick raw strings count as strings), then:

1. **Imports tell it what names mean**, including aliases (`mrand "math/rand"`) and versioned
   paths (`"math/rand/v2"` is used as `rand`). Each import of a crypto package is itself a
   finding, just like an import in Python.
2. **Every `package.Name` is looked up**: first the exact name (`sha256.Sum224` is SHA-224,
   `cipher.NewCBCEncrypter` is CBC, `cipher.NewGCM` is AES-GCM), then the package (anything else
   in `crypto/sha256` is SHA-256). A path also covers its sub-packages, so
   `circl/kem/mlkem/mlkem768` is ML-KEM.
3. **Some calls are read in detail:** `rsa.GenerateKey(rand.Reader, 1024)` is RSA under 2048
   bits, `hmac.New(sha1.New, key)` is HMAC-SHA1 (not SHA-1 on its own), and `pbkdf2.Key(...)`
   reports its iteration count (both the standard library and `golang.org/x/crypto` versions).

Go has two packages called `rand`: **`crypto/rand`** (secure) and **`math/rand`** (predictable).
Because names are resolved through each file's own imports, they're never confused, and
`math/rand` is only flagged when it's making a token, key, OTP or similar.

Also covered: `crypto/mlkem` and the hybrid TLS group `tls.X25519MLKEM768`, Cloudflare CIRCL's
ML-DSA / SLH-DSA, `crypto/ecdh` (X25519 vs. NIST curves), `crypto/dsa` parameter sizes,
`x509.SHA1WithRSA`-style signature algorithms, `tls.Config{InsecureSkipVerify: true}`, old
`tls.VersionTLS10/11` and weak cipher suites (`TLS_RSA_WITH_RC4_128_SHA` is RC4 plus static RSA
key exchange). The `vendor/` folder of copied dependencies is skipped.

### Certificates and keys

The code scanners find crypto that code *uses*. This one reads crypto *material* in the repository:
`.pem`, `.crt`, `.cer`, `.der`, `.key`, `.pub` and `.csr` files, in text (PEM) or binary (DER) form.

- **X.509 certificates:** the key type and size (RSA-1024 is BROKEN; ECDSA, RSA-2048 and Ed25519
  are LEGACY because they're quantum-vulnerable; ML-DSA is CURRENT), the signature hash (a SHA-1
  signed certificate is BROKEN), the subject, and whether it has **expired**. A bundle with many
  certificates reports each one at its own line, and a *Certificates* table summarises them.
- **Private keys:** an **unencrypted private key in the repository is BROKEN** on its own,
  whatever its algorithm. Anyone who can read the repo, or an old commit, holds the key. A
  password-protected key is listed under *Notes* and never opened.
- **Also:** public keys, certificate signing requests, OpenSSH public and private keys
  (`ssh-rsa`, `ssh-ed25519`, `ssh-dss`...) and Diffie-Hellman parameter files.
- **In the CBOM**, each certificate becomes a CycloneDX `certificate` asset with its subject,
  issuer, validity dates and signature algorithm, linked to the algorithms it depends on.

Findings show only facts *about* a key. The report's code column shows the
`-----BEGIN CERTIFICATE-----` style marker, never the key material.

### Limitations

- It's static analysis: values computed at runtime (`key_size=bits`) can't be read, so those
  findings fall back to the algorithm's normal grade.
- The `random`-for-secrets and password-hash checks are name-based heuristics. They can miss
  cases or occasionally flag harmless code.
- Java, JavaScript and Go are matched by text patterns, not fully parsed. Links across lines (a
  key-pair variable and its `initialize` call, a constant and where it's used) work within one
  file, not across files.
- Python, Java, JavaScript, TypeScript and Go for now. Password-protected keys and keystores
  (`.p12`, `.jks`) aren't opened.

## Tests

```bash
python -m pytest
```

The sample files in [`tests/samples/`](tests/samples) (Python),
[`tests/samples_java/`](tests/samples_java) (Java), [`tests/samples_js/`](tests/samples_js)
(JavaScript and TypeScript) and [`tests/samples_go/`](tests/samples_go) (Go) contain known weak
and strong crypto. Each
line ends with an `expect: ...` comment naming what the scanner must find there, and the tests
check the scanner finds exactly that: nothing missed, nothing extra. Certificates and keys are
**generated during the tests and never committed**: the repository contains no key material.
(Modern `cryptography` refuses to *create* SHA-1-signed certificates, so
[`tests/conftest.py`](tests/conftest.py) builds a SHA-256 one, swaps the algorithm label and signs
it again with SHA-1, giving a genuine old-style certificate to test against.) CBOM output is checked
against the official CycloneDX 1.6 schema, and SARIF output against the official OASIS SARIF
2.1.0 schema (kept in [`tests/schemas/`](tests/schemas)). CI runs the suite on
Python 3.10 to 3.14 (Linux) and Windows.

## Roadmap

- [x] Python scanning, grading and terminal report
- [x] `--cbom out.json`: CycloneDX 1.6 CBOM output, schema-validated in the tests
- [x] Java scanning (JCA, Commons Codec, Guava, Bouncy Castle PQC)
- [x] JavaScript / TypeScript scanning (Node crypto, WebCrypto, JWT, crypto-js)
- [x] Go scanning (standard library, golang.org/x/crypto, CIRCL post-quantum)
- [x] Certificates and keys (key type and size, signature hash, expiry, committed private keys)
- [x] SARIF output and GitHub code scanning, `--exclude`, `cryptoinv: ignore` comments
- [ ] Installable package (`pip install`, a `cryptoinv` command) and tagged releases
