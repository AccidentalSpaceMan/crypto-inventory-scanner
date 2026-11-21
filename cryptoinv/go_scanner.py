"""Find cryptography in Go source code.

Go organises crypto by package, and every package is imported by its full path:
`import "crypto/md5"`, `import "golang.org/x/crypto/bcrypt"`. That makes Go friendly to scan:

1. Read the imports, so we know which local name means which package (including aliases like
   `import mrand "math/rand"` and versioned paths like "math/rand/v2", whose name is "rand").
2. Find every `name.Symbol` that uses one of those packages, in the masked text (comments and
   string contents blanked, see textscan.py), and look it up in the "go" section of rules.json:
   first the exact symbol (sha256.Sum224 is SHA-224), then the package (anything else in
   crypto/sha256 is SHA-256).
3. For a few functions, read the arguments: rsa.GenerateKey(rand.Reader, 1024) is RSA under 2048
   bits, hmac.New(sha1.New, key) is HMAC-SHA1, pbkdf2.Key(...) has an iteration count.

Two Go packages share the short name "rand": crypto/rand (secure) and math/rand (predictable).
Because names are resolved through the file's own imports, they are never confused.
"""
from __future__ import annotations

import re

from .rules import Rules
from .scanner import Finding
from .textscan import STRING, TextScanner, closing_paren, split_args

GO_IDENT = r"[A-Za-z_]\w*"
IMPORT_SPEC = re.compile(rf"(?:({GO_IDENT}|\.)\s+)?({STRING})")
IMPORT_SINGLE = re.compile(rf"\bimport\s+(?:({GO_IDENT}|\.)\s+)?({STRING})")
IMPORT_BLOCK = re.compile(r"\bimport\s*\(")
SELECTOR = re.compile(rf"(?<![\w.])({GO_IDENT})\s*\.\s*({GO_IDENT})")
FUNC_DECLS = [
    re.compile(rf"(?m)^func\s+(?:\([^)]*\)\s*)?({GO_IDENT})\s*[\[(]"),
    re.compile(rf"\b({GO_IDENT})\s*:?=\s*func\s*\("),
]


class _GoScan(TextScanner):
    backticks = True   # Go raw strings: `like this`

    def __init__(self, rules: Rules, path: str, source: str):
        self.go = rules.go
        super().__init__(rules, path, source)
        self.imports: dict[str, str] = {}   # local package name -> import path
        self.consumed: set[int] = set()      # selector offsets already explained by a call

    def function_names(self) -> list[tuple[int, str]]:
        found = []
        for pattern in FUNC_DECLS:
            found += [(m.start(), m.group(1)) for m in pattern.finditer(self.masked)]
        return found

    # -- imports

    def _imports(self) -> None:
        specs = [(m.group(1), m.group(2), m.span(2)) for m in IMPORT_SINGLE.finditer(self.masked)]
        for block in IMPORT_BLOCK.finditer(self.masked):
            end = closing_paren(self.masked, block.end() - 1) or len(self.masked)
            specs += [(m.group(1), m.group(2), m.span(2))
                      for m in IMPORT_SPEC.finditer(self.masked, block.end(), end)]
        for alias, token, span in specs:
            path = self.string_value(token, span)
            if not path:
                continue
            if alias != ".":
                parts = path.split("/")
                name = parts[-2] if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]) else parts[-1]
                self.imports[alias or name] = path       # alias "_" is harmless: never used
            if path not in self.go.secret_context:
                for alg_id in self.go.package_ids(path):
                    self.report(span[0], alg_id, f'import "{path}"')

    # -- lookups

    def resolve(self, local: str, name: str) -> tuple[str | None, tuple[str, ...]]:
        """("sha256", "Sum224") -> ("crypto/sha256", ("SHA224",))."""
        path = self.imports.get(local)
        if path is None:
            return None, ()
        full = f"{path}.{name}"
        if full in self.go.symbols:
            return path, self.go.symbols[full]
        if path == "crypto/tls" and name.startswith("TLS_"):
            return path, self._tls_suite(name)
        return path, self.go.package_ids(path)

    def _tls_suite(self, name: str) -> tuple[str, ...]:
        parts = name.upper().split("_")
        ids = [self.go.tls_suite_parts[p] for p in parts if p in self.go.tls_suite_parts]
        if parts[1:3] == ["RSA", "WITH"]:
            ids.append("RSA")   # static RSA key exchange: no forward secrecy, quantum-vulnerable
        return tuple(dict.fromkeys(ids))

    def hash_in(self, span: tuple[int, int]) -> str | None:
        """The hash named by an argument like sha1.New or sha256.New; marks it as explained."""
        m = SELECTOR.search(self.masked, span[0], span[1])
        if not m:
            return None
        _, ids = self.resolve(m.group(1), m.group(2))
        hashes = [i for i in ids if self.rules.algorithms[i].fast_hash]
        if hashes:
            self.consumed.add(m.start())
            return hashes[0]
        return None

    # -- the main pass

    def _selectors(self) -> None:
        for m in SELECTOR.finditer(self.masked):
            if m.start() in self.consumed:
                continue
            local, name = m.group(1), m.group(2)
            path, ids = self.resolve(local, name)
            if path is None:
                continue
            symbol = f"{local}.{name}"
            call = self.go.calls.get(f"{path}.{name}")
            after = self.masked[m.end():m.end() + 40].lstrip()
            if call and after.startswith("("):
                self._call(call, m.end() + self.masked[m.end():].index("("), m.start(), symbol)
                continue
            if path in self.go.secret_context and not self.in_secret_context(m.start()):
                continue
            for alg_id in ids:
                self.report(m.start(), alg_id, symbol)

    def _call(self, call: dict, paren: int, offset: int, symbol: str) -> None:
        args = split_args(self.masked, paren)
        alg_id, details = call["algorithm"], []

        def arg(key):
            i = call.get(key)
            return args[i] if i is not None and i < len(args) else None

        if arg("hash_arg"):
            hash_id = self.hash_in(arg("hash_arg"))
            if hash_id:
                details.append(f"hash: {self.rules.algorithms[hash_id].name}")
                alg_id = call.get("variants", {}).get(hash_id, alg_id)
        if arg("iterations_arg") and self.go.pbkdf2:
            count = self.arg_int(arg("iterations_arg"))
            if count is not None:
                rule = self.go.pbkdf2
                alg_id = rule["below"] if count < rule["min"] else rule["otherwise"]
                details.insert(0, f"iterations={count:,}")
        if arg("key_size_arg") and alg_id in self.go.key_size:
            bits = self.arg_int(arg("key_size_arg"))
            if bits is not None:
                minimum, below = self.go.key_size[alg_id]
                alg_id = below if bits < minimum else alg_id
                details.insert(0, f"key_size={bits:,}")
        self.report(offset, alg_id, symbol, ", ".join(details))

    def scan(self) -> list[Finding]:
        self._imports()
        self._selectors()
        for pattern, alg_id in self.go.patterns:
            for m in pattern.finditer(self.masked):
                self.report(m.start(), alg_id, " ".join(m.group(0).split())[:60])
        return self.sorted_findings()


def scan_go_source(source: bytes | str, path: str, rules: Rules) -> list[Finding]:
    """Scan one Go file's source code."""
    if rules.go is None:
        return []
    text = source.decode("utf-8-sig", errors="replace") if isinstance(source, bytes) else source
    return _GoScan(rules, path, text).scan()
