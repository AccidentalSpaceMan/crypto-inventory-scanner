"""Find cryptography in JavaScript and TypeScript source code.

Like the Java scanner this works on masked text (see textscan.py): comments and string contents
are blanked so that only real code can match, then the real strings are read back by position.
JavaScript adds backtick `template strings` and /regex literals/ to the masking.

What it looks for:

- **Node's crypto module**, wherever it was imported (`require('crypto')`, `import ... from
  'node:crypto'`, destructured names, or the usual global `crypto`): createHash('md5'),
  createHmac('sha1'), createCipheriv('aes-128-ecb'), generateKeyPairSync('rsa',
  { modulusLength: 1024 }), pbkdf2Sync(pw, salt, 1000, ...), getDiffieHellman('modp2')...
- **WebCrypto** (browsers, Deno, Node): algorithm objects such as { name: 'AES-GCM' } or
  { name: 'PBKDF2', hash: 'SHA-1', iterations: 1000 }, and string arguments to crypto.subtle calls.
- **JSON Web Tokens** (jsonwebtoken): the algorithm option of jwt.sign / jwt.verify, including
  the dangerous 'none'.
- **crypto-js, bcrypt, argon2** via patterns and imports listed in rules.json.
- **Math.random()** used for secrets, and TLS checks turned off.
"""
from __future__ import annotations

import re

from .rules import Rules
from .scanner import PASSWORD_WORDS, Finding, _words
from .textscan import (IDENT, INT_OR_NAME, STRING, TextScanner, closing_paren, enclosing_braces,
                       split_args)

NODE_MODULES = {"crypto", "node:crypto"}
JWT_MODULES = {"jsonwebtoken"}

REQUIRE = re.compile(rf"\brequire\s*\(\s*({STRING})\s*\)")
IMPORT_FROM = re.compile(rf"\bimport\s+(?:type\s+)?([\w$*\s{{}},]+?)\s+from\s*({STRING})")
IMPORT_BARE = re.compile(rf"\bimport\s*({STRING})")
BIND_BEFORE = re.compile(rf"(?:\b(?:const|let|var)\s+|\bimport\s+)(?:({IDENT})|\{{([^}}]*)\}})\s*=\s*$")
MEMBER_CALL = re.compile(rf"(?<![\w$.])({IDENT})\s*\.\s*({IDENT})\s*\(")
BARE_CALL = re.compile(rf"(?<![\w$.])({IDENT})\s*\(")
SUBTLE_CALL = re.compile(rf"\bsubtle\s*\.\s*({IDENT})\s*\(")
NAME_KEY = re.compile(rf"(?<![\w$])name\s*:\s*({STRING}|{IDENT})")
HASH_KEY = re.compile(rf"(?<![\w$])hash\s*:\s*(?:({STRING}|{IDENT})|\{{\s*name\s*:\s*({STRING}|{IDENT}))")
ITERATIONS_KEY = re.compile(rf"(?<![\w$])iterations\s*:\s*{INT_OR_NAME}")
KEY_SIZE_KEY = re.compile(rf"(?<![\w$])(?:modulusLength|primeLength)\s*:\s*{INT_OR_NAME}")
ALGORITHM_KEY = re.compile(rf"(?<![\w$])algorithms?\s*:\s*(\[[^\]]*\]|{STRING}|{IDENT})")
TLS_KEY = re.compile(rf"(?<![\w$])(secureProtocol|minVersion|maxVersion)\s*:\s*({STRING}|{IDENT})")
NODE_TLS_ENV = re.compile(rf"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*({STRING}|\d+)")
MATH_RANDOM = re.compile(r"\bMath\s*\.\s*random\s*\(")
UPDATE_CALL = re.compile(r"\s*\.\s*update\s*\(")
FUNCTION_DECLS = [
    re.compile(rf"\bfunction\s*\*?\s*({IDENT})\s*\("),
    re.compile(rf"(?<![\w$.])({IDENT})\s*[:=]\s*(?:async\s+)?"
               rf"(?:function\b|\([^()]*\)\s*(?::[^=;{{]+)?=>|{IDENT}\s*=>)"),
    re.compile(rf"(?m)^[ \t]*(?:(?:async|static|public|private|protected|get|set)\s+)*"
               rf"({IDENT})\s*\([^()]*\)\s*(?::\s*[^{{;]+?)?\s*\{{"),
]
_NOT_FUNCTIONS = {"if", "for", "while", "switch", "catch", "function", "return", "with"}

NODE_FUNCS = {
    "createHash", "createHmac", "createCipheriv", "createDecipheriv", "createCipher",
    "createDecipher", "createSign", "createVerify", "sign", "verify", "generateKeyPair",
    "generateKeyPairSync", "generateKey", "generateKeySync", "pbkdf2", "pbkdf2Sync", "scrypt",
    "scryptSync", "hkdf", "hkdfSync", "argon2", "argon2Sync", "randomBytes", "randomFill",
    "randomFillSync", "randomInt", "randomUUID", "getRandomValues", "createECDH",
    "createDiffieHellman", "getDiffieHellman", "createDiffieHellmanGroup", "publicEncrypt",
    "privateDecrypt", "privateEncrypt", "publicDecrypt",
}
_RANDOM_FUNCS = {"randomBytes", "randomFill", "randomFillSync", "randomInt", "randomUUID", "getRandomValues"}
_RSA_FUNCS = {"publicEncrypt", "privateDecrypt", "privateEncrypt", "publicDecrypt"}
_HMAC_VARIANTS = {"SHA1": "HMAC_SHA1", "MD5": "HMAC_MD5"}


class _JsScan(TextScanner):
    js = True

    def __init__(self, rules: Rules, path: str, source: str):
        self.jsr = rules.javascript
        super().__init__(rules, path, source)
        self.node_aliases = {"crypto"}       # names that refer to the whole crypto module
        self.node_names: dict[str, str] = {}  # local name -> crypto function it was imported as
        self.jwt_aliases = {"jwt"}
        self.jwt_names: dict[str, str] = {}
        self.webcrypto_iterations: list[int] = []

    def function_names(self) -> list[tuple[int, str]]:
        found = []
        for pattern in FUNCTION_DECLS:
            found += [(m.start(), m.group(1)) for m in pattern.finditer(self.masked)
                      if m.group(1) not in _NOT_FUNCTIONS]
        return found

    # -- name lookups

    def ids(self, table: dict, name: str | None) -> tuple[str, ...]:
        return table.get(name.strip().upper(), ()) if name else ()

    def hash_name(self, alg_id: str) -> str:
        return self.rules.algorithms[alg_id].name

    def cipher(self, name: str) -> list[tuple[str, str]]:
        """OpenSSL cipher names: "aes-128-ecb" -> [AES, ECB]; "aes256" -> [AES, CBC]; "aes-256-gcm" -> [AES-GCM]."""
        parts = name.strip().lower().split("-")
        mode = parts.pop() if len(parts) > 1 and parts[-1].upper() in self.jsr.cipher_modes else None
        base = "-".join(parts)
        if base.startswith("id-"):
            base = base[3:]
        if base.upper() not in self.jsr.ciphers:
            base = re.sub(r"-?\d+$", "", base)      # aes-256 / aes256 -> aes; rc4-40 -> rc4
        results = []
        for alg_id in self.jsr.ciphers.get(base.upper(), ()):
            alg = self.rules.algorithms[alg_id]
            if alg.primitive != "block-cipher" or alg.mode:
                results.append((alg_id, ""))
                continue
            detail = ""
            if mode is None:
                mode = self.jsr.cipher_default_modes.get(base, self.jsr.cipher_default_modes.get("*", "cbc"))
                detail = f"no mode in the name: OpenSSL uses {mode.upper()}"
            mode_ids = self.jsr.cipher_modes.get(mode.upper(), ())
            if alg_id == "AES" and any(m in ("AES_GCM", "AES_AEAD_OTHER") for m in mode_ids):
                results += [(m, detail) for m in mode_ids]
            else:
                results += [(alg_id, "")] + [(m, detail) for m in mode_ids]
        return results

    def graded_pbkdf2(self, count: int | None) -> tuple[str, str]:
        rule = self.jsr.pbkdf2
        if count is None or not rule:
            return "PBKDF2", ""
        return (rule["below"] if count < rule["min"] else rule["otherwise"]), f"iterations={count:,}"

    def sized(self, alg_id: str, span: tuple[int, int] | None) -> tuple[str, str]:
        """Apply the key-size rule using modulusLength / primeLength found inside span."""
        rule = self.jsr.key_size.get(alg_id)
        if not rule or not span:
            return alg_id, ""
        m = KEY_SIZE_KEY.search(self.masked, span[0], span[1])
        bits = self.int_value(m.group(1)) if m else None
        if bits is None:
            return alg_id, ""
        return (rule[1] if bits < rule[0] else alg_id), f"key_size={bits:,}"

    # -- imports

    def _imports(self) -> None:
        for m in REQUIRE.finditer(self.masked):
            module = self.string_value(m.group(1), m.span(1))
            self._module_finding(module, m.start())
            bind = BIND_BEFORE.search(self.masked, max(0, m.start() - 300), m.start())
            if bind:
                self._bind(module, bind.group(1), bind.group(2), ":")
        for m in IMPORT_FROM.finditer(self.masked):
            module = self.string_value(m.group(2), m.span(2))
            self._module_finding(module, m.start())
            clause = m.group(1)
            named = re.search(r"\{([^}]*)\}", clause)
            default = None
            for part in re.sub(r"\{[^}]*\}", "", clause).split(","):
                part = part.strip()
                if part:
                    default = re.split(r"\s+as\s+", part)[-1].strip()   # "x" or "* as x"
            self._bind(module, default, named.group(1) if named else None, "as")
        for m in IMPORT_BARE.finditer(self.masked):
            self._module_finding(self.string_value(m.group(1), m.span(1)), m.start())

    def _module_finding(self, module: str | None, offset: int) -> None:
        for alg_id in self.jsr.modules.get(module or "", ()):
            self.report(offset, alg_id, f"import '{module}'")

    def _bind(self, module: str | None, default: str | None, named: str | None, sep: str) -> None:
        if module in NODE_MODULES:
            aliases, names = self.node_aliases, self.node_names
        elif module in JWT_MODULES:
            aliases, names = self.jwt_aliases, self.jwt_names
        else:
            return
        if default:
            aliases.add(default)
        for item in (named or "").split(","):
            item = re.sub(r"^\s*type\s+", "", item).strip()
            if not item:
                continue
            pieces = re.split(r"\s+as\s+", item) if sep == "as" else item.split(":")
            original, local = pieces[0].strip(), pieces[-1].strip()
            names[local] = original

    # -- Node crypto calls

    def _calls(self) -> None:
        for m in MEMBER_CALL.finditer(self.masked):
            obj, func = m.group(1), m.group(2)
            if obj in self.node_aliases and func in NODE_FUNCS:
                self._node_call(func, m.end() - 1, m.start(), f"{obj}.")
            elif obj in self.jwt_aliases and func in ("sign", "verify"):
                self._jwt_call(m.end() - 1, m.start(), f"{obj}.{func}")
        for m in BARE_CALL.finditer(self.masked):
            local = m.group(1)
            if self.node_names.get(local) in NODE_FUNCS:
                self._node_call(self.node_names[local], m.end() - 1, m.start(), "")
            elif self.jwt_names.get(local) in ("sign", "verify"):
                self._jwt_call(m.end() - 1, m.start(), local)

    def _node_call(self, func: str, paren: int, offset: int, prefix: str) -> None:
        args = split_args(self.masked, paren)
        string = self.arg_string(args[0]) if args else None
        symbol = f"{prefix}{func}('{string}')" if string else f"{prefix}{func}(...)"
        report = lambda alg_id, detail="": self.report(offset, alg_id, symbol, detail)  # noqa: E731

        if func == "createHash":
            password = self._hashes_password(paren)
            for alg_id in self.ids(self.jsr.node_names, string):
                if password and self.rules.algorithms[alg_id].fast_hash:
                    alg_id = "UNSALTED_PASSWORD_HASH"
                report(alg_id)
        elif func == "createHmac":
            hashes = [a for a in self.ids(self.jsr.node_names, string) if self.rules.algorithms[a].fast_hash]
            if hashes:
                report(_HMAC_VARIANTS.get(hashes[0], "HMAC"), f"hash: {self.hash_name(hashes[0])}")
        elif func in ("createCipheriv", "createDecipheriv", "createCipher", "createDecipher"):
            deprecated = func in ("createCipher", "createDecipher")
            for alg_id, detail in self.cipher(string or ""):
                if deprecated:
                    detail = "; ".join(filter(None, [detail, "deprecated: weak MD5-based key derivation, no IV"]))
                report(alg_id, detail)
        elif func in ("createSign", "createVerify", "sign", "verify"):
            for alg_id in self.ids(self.jsr.node_names, string):
                report(alg_id)
        elif func in ("generateKeyPair", "generateKeyPairSync", "generateKey", "generateKeySync"):
            options = args[1] if len(args) > 1 else None
            for alg_id in self.ids(self.jsr.node_names, string):
                report(*self.sized(alg_id, options))
        elif func in ("pbkdf2", "pbkdf2Sync"):
            alg_id, detail = self.graded_pbkdf2(self.arg_int(args[2]) if len(args) > 2 else None)
            digest = self.arg_string(args[4]) if len(args) > 4 else None
            hashes = self.ids(self.jsr.node_names, digest)
            if hashes:
                detail = ", ".join(filter(None, [detail, f"hash: {self.hash_name(hashes[0])}"]))
            self.report(offset, alg_id, f"{prefix}{func}(...)", detail)
        elif func in ("scrypt", "scryptSync"):
            report("SCRYPT")
        elif func in ("hkdf", "hkdfSync"):
            hashes = self.ids(self.jsr.node_names, string)
            report("HKDF", f"hash: {self.hash_name(hashes[0])}" if hashes else "")
        elif func in ("argon2", "argon2Sync"):
            report("ARGON2")
        elif func in _RANDOM_FUNCS:
            self.report(offset, "CSPRNG", f"{prefix}{func}(...)")
        elif func == "createECDH":
            report("ECDH")
        elif func == "createDiffieHellman":
            bits = self.arg_int(args[0]) if args else None
            minimum, below = self.jsr.key_size.get("DH", (0, "DH"))
            if bits is None:
                self.report(offset, "DH", f"{prefix}{func}(...)")
            else:
                self.report(offset, below if bits < minimum else "DH", f"{prefix}{func}({bits})", f"key_size={bits:,}")
        elif func in ("getDiffieHellman", "createDiffieHellmanGroup"):
            bits = self.jsr.dh_groups.get((string or "").lower())
            minimum, below = self.jsr.key_size.get("DH", (0, "DH"))
            if bits is None:
                report("DH")
            else:
                report(below if bits < minimum else "DH", f"group {string} = {bits:,} bits")
        elif func in _RSA_FUNCS:
            self.report(offset, "RSA", f"{prefix}{func}(...)")

    def _hashes_password(self, paren: int) -> bool:
        """Is createHash(...) immediately followed by .update(<something named like a password>)?"""
        close = closing_paren(self.masked, paren)
        if close is None:
            return False
        update = UPDATE_CALL.match(self.masked, close + 1)
        if not update:
            return False
        end = closing_paren(self.masked, update.end() - 1) or update.end()
        names = re.findall(IDENT, self.masked[update.end():end])
        return any(w in PASSWORD_WORDS for n in names for w in _words(n))

    # -- JSON Web Tokens

    def _jwt_call(self, paren: int, offset: int, symbol: str) -> None:
        args = split_args(self.masked, paren)
        if not args:
            return
        for m in ALGORITHM_KEY.finditer(self.masked, args[0][0], args[-1][1]):
            for s in re.finditer(rf"{STRING}|{IDENT}", m.group(1)):
                start = m.start(1) + s.start()
                value = self.string_value(s.group(0), (start, start + len(s.group(0))))
                for alg_id in self.ids(self.jsr.jwt, value):
                    self.report(offset, alg_id, f"{symbol}(..., {{ algorithm: '{value}' }})")

    # -- WebCrypto

    def _webcrypto(self) -> None:
        table = self.jsr.webcrypto
        planned, consumed = [], set()
        for m in NAME_KEY.finditer(self.masked):
            value = self.string_value(m.group(1), m.span(1))
            ids = list(self.ids(table, value))
            if not ids:
                continue
            span = enclosing_braces(self.masked, m.start())
            details = []
            if span and any(i in ("HMAC", "PBKDF2", "HKDF") for i in ids):
                h = HASH_KEY.search(self.masked, span[0], span[1])
                if h:
                    group = 1 if h.group(1) else 2
                    hash_ids = self.ids(table, self.string_value(h.group(group), h.span(group)))
                    if hash_ids:
                        details.append(f"hash: {self.hash_name(hash_ids[0])}")
                        if group == 2:  # the nested { name: 'SHA-1' } is part of this algorithm
                            consumed.add(h.start() + h.group(0).rindex("name"))
                        if "HMAC" in ids:
                            ids = [_HMAC_VARIANTS.get(hash_ids[0], "HMAC")]
            if "PBKDF2" in ids and span:
                it = ITERATIONS_KEY.search(self.masked, span[0], span[1])
                count = self.int_value(it.group(1)) if it else None
                if count is not None:
                    self.webcrypto_iterations.append(count)
                alg_id, detail = self.graded_pbkdf2(count)
                ids = [alg_id if i == "PBKDF2" else i for i in ids]
                details.insert(0, detail)
            sized = [self.sized(i, span) for i in ids]
            planned.append((m.start(), sized, details, value))

        for offset, sized, details, value in planned:
            if offset in consumed:
                continue
            for alg_id, size_detail in sized:
                detail = ", ".join(filter(None, [size_detail, *details]))
                self.report(offset, alg_id, f"{{ name: '{value}' }}", detail)

        for m in SUBTLE_CALL.finditer(self.masked):
            for span in split_args(self.masked, m.end() - 1):
                value = self.arg_string(span)
                for alg_id in self.ids(table, value):
                    detail = ""
                    if alg_id == "PBKDF2" and self.webcrypto_iterations:
                        alg_id, detail = self.graded_pbkdf2(min(self.webcrypto_iterations))
                    self.report(m.start(), alg_id, f"subtle.{m.group(1)}('{value}')", detail)

    # -- randomness, TLS, patterns

    def _insecure_random(self) -> None:
        for m in MATH_RANDOM.finditer(self.masked):
            if self.in_secret_context(m.start()):
                self.report(m.start(), "INSECURE_RANDOM", "Math.random()")

    def _tls(self) -> None:
        for m in TLS_KEY.finditer(self.masked):
            value = self.string_value(m.group(2), m.span(2))
            for alg_id in self.ids(self.jsr.tls, value):
                self.report(m.start(), alg_id, f"{m.group(1)}: '{value}'")
        for m in NODE_TLS_ENV.finditer(self.masked):
            token = m.group(1)
            value = token if token[0].isdigit() else self.string_value(token, m.span(1))
            if (value or "").strip() == "0":
                self.report(m.start(), "TLS_NO_VERIFY", "NODE_TLS_REJECT_UNAUTHORIZED = '0'")

    def scan(self) -> list[Finding]:
        self._imports()
        self._calls()
        self._webcrypto()
        self._insecure_random()
        self._tls()
        for pattern, alg_id in self.jsr.patterns:
            for m in pattern.finditer(self.masked):
                self.report(m.start(), alg_id, " ".join(m.group(0).split())[:60])
        return self.sorted_findings()


def scan_js_source(source: bytes | str, path: str, rules: Rules) -> list[Finding]:
    """Scan one JavaScript or TypeScript file's source code."""
    if rules.javascript is None:
        return []
    text = source.decode("utf-8-sig", errors="replace") if isinstance(source, bytes) else source
    return _JsScan(rules, path, text).scan()
