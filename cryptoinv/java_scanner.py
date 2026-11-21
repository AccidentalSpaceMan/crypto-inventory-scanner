"""Find cryptography in Java source code.

Python ships a parser for Python (`ast`) but not for Java, so this scanner works on the text, in
two careful steps:

1. **Mask.** Comments are blanked out, and so is the inside of every string literal, in a copy of
   the file. Each blanked character becomes a space, so every offset and line number stays the
   same. Searching the masked copy means a comment or string that merely *mentions* "MD5" can
   never match.
2. **Match.** Java's crypto API (the JCA) names algorithms as strings:
   `Cipher.getInstance("AES/GCM/NoPadding")`, `MessageDigest.getInstance("SHA-256")`,
   `Signature.getInstance("SHA256withRSA")`. The scanner finds those calls in the masked copy,
   then reads the real string from the original at the same position and looks it up in the
   "java" section of rules.json.

It also links simple facts across lines: `kpg = KeyPairGenerator.getInstance("RSA")` followed by
`kpg.initialize(1024)` is RSA under 2048 bits, and `static final String ALG = "DES"` is resolved
when `Cipher.getInstance(ALG)` uses it.
"""
from __future__ import annotations

import bisect
import re

from .rules import JavaRules, Rules
from .scanner import SECRET_WORDS, Finding, _words

_CLASSES = ("MessageDigest|Cipher|Mac|Signature|KeyPairGenerator|KeyGenerator|KeyAgreement|"
            "SecretKeyFactory|KeyFactory|SSLContext|SecureRandom|KEM")
_STRING_OR_NAME = r'("[^"\n]*"|[A-Za-z_][\w.]*)'
GET_INSTANCE = re.compile(rf"\b({_CLASSES})\s*\.\s*getInstance\s*\(\s*{_STRING_OR_NAME}")
SECRET_KEY_SPEC = re.compile(rf"\bnew\s+SecretKeySpec\s*\([^;]*?,\s*{_STRING_OR_NAME}\s*\)")
STRING_CONST = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*("[^"\n]*")\s*[;,]')
INT_CONST = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(\d[\d_]*)\s*[;,]")
INT_OR_NAME = r"(\d[\d_]*|[A-Za-z_]\w*)"
INITIALIZE = re.compile(rf"\b(\w+)\s*\.\s*initialize\s*\(\s*{INT_OR_NAME}\s*[,)]")
RSA_SPEC = re.compile(rf"\bnew\s+RSAKeyGenParameterSpec\s*\(\s*{INT_OR_NAME}")
PBE_KEY_SPEC = re.compile(r"\bnew\s+PBEKeySpec\s*\(")
ENABLED_PROTOCOLS = re.compile(r"\bsetEnabledProtocols\s*\(")
ASSIGNED_TO = re.compile(r"\b(\w+)\s*=\s*$")

RANDOM_VAR = re.compile(r"\b(\w+)\s*=\s*new\s+(?:java\.util\.)?Random\s*\(")
INSECURE_RANDOM = [
    re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\("),
    re.compile(r"\bMath\s*\.\s*random\s*\("),
    re.compile(r"\bThreadLocalRandom\s*\.\s*current\s*\(\s*\)\s*\.\s*\w+\s*\("),
    re.compile(r"\bRandomStringUtils\s*\.\s*random\w*\s*\("),
]
METHOD = re.compile(
    r"(?m)^[ \t]*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|"
    r"default|native)\s+)*[\w.<>\[\],? ]+?\s+(\w+)\s*\([^;{)]*\)\s*(?:throws\s+[\w.,\s]+?)?\{")
_NOT_METHODS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else", "try"}


def mask(source: str) -> tuple[str, str]:
    """Return (source without comments, source without comments or string contents).

    Both keep exactly the same length and line breaks as the original.
    """
    no_comments, masked = list(source), list(source)
    n, i = len(source), 0

    def blank(chars, start, end):
        for k in range(start, end):
            if chars[k] != "\n":
                chars[k] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            blank(no_comments, i, end), blank(masked, i, end)
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(no_comments, i, end), blank(masked, i, end)
            i = end
        elif source.startswith('"""', i):                       # text block (Java 15+)
            end = source.find('"""', i + 3)
            end = n if end < 0 else end
            blank(masked, i + 3, end)
            i = end + 3
        elif source[i] in "\"'":                                 # string or char literal
            quote, j = source[i], i + 1
            while j < n and source[j] != quote and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            j = min(j, n)
            blank(masked, i + 1, j)
            i = j + 1
        else:
            i += 1
    return "".join(no_comments), "".join(masked)


def _split_args(text: str, open_paren: int) -> list[tuple[int, int]]:
    """Spans of the top-level arguments of the call whose "(" is at open_paren."""
    depth, start, spans = 0, open_paren + 1, []
    for i in range(open_paren, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                spans.append((start, i))
                return spans
        elif c == "," and depth == 1:
            spans.append((start, i))
            start = i + 1
    return spans


class _JavaScan:
    def __init__(self, rules: Rules, path: str, source: str):
        self.rules, self.java, self.path = rules, rules.java, path
        self.source = source
        self.text, self.masked = mask(source)  # original minus comments / minus strings too
        self.lines = source.splitlines()
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", source)]
        self.findings: list[Finding] = []
        self._seen: set[tuple[int, str]] = set()
        self.strings = {m.group(1): self._literal(m.span(2)) for m in STRING_CONST.finditer(self.masked)}
        self.ints = {m.group(1): int(m.group(2).replace("_", "")) for m in INT_CONST.finditer(self.masked)}
        self.methods = [(m.start(), m.group(1)) for m in METHOD.finditer(self.masked)
                        if m.group(1) not in _NOT_METHODS]

    # -- helpers

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def _literal(self, span: tuple[int, int]) -> str:
        """Read a string literal's real contents (from the unmasked text) by its span."""
        return self.text[span[0] + 1:span[1] - 1]

    def string_value(self, token: str, span: tuple[int, int]) -> str | None:
        """A string literal or the name of a String constant defined in this file."""
        if token.startswith('"'):
            return self._literal(span)
        return self.strings.get(token.rsplit(".", 1)[-1])

    def int_value(self, token: str) -> int | None:
        if token[0].isdigit():
            return int(token.replace("_", ""))
        return self.ints.get(token)

    def report(self, offset: int, alg_id: str, symbol: str, detail: str = "") -> None:
        line = self.line_of(offset)
        if (line, alg_id) in self._seen:
            return
        self._seen.add((line, alg_id))
        code = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        self.findings.append(Finding(self.path, line, self.rules.algorithms[alg_id], symbol, detail, code))

    def in_secret_context(self, offset: int) -> bool:
        line = self.line_of(offset)
        start = self.line_starts[line - 1]
        end = self.line_starts[line] if line < len(self.line_starts) else len(self.masked)
        names = re.findall(r"[A-Za-z_]\w*", self.masked[start:end])
        i = bisect.bisect_right(self.methods, (offset, "￿")) - 1
        if i >= 0:
            names.append(self.methods[i][1])
        return any(w in SECRET_WORDS for n in names for w in _words(n))

    # -- turning Java algorithm names into findings

    def lookup(self, name: str) -> list[str]:
        """"SHA-256" -> [SHA256]; "SHA1withRSA" -> [SHA1, RSA]; "PBEWithMD5AndDES" -> [MD5, DES]."""
        key = name.strip().upper()
        if key in self.java.names:
            return [self.java.names[key]]
        if "WITH" not in key:
            return []
        if key.startswith("PBEWITH"):
            parts = key[len("PBEWITH"):].split("AND")
        else:
            digest, _, rest = key.partition("WITH")
            parts = [digest, *rest.split("AND")]
        ids = []
        for part in parts:
            part = part.split("/")[0].replace("INP1363FORMAT", "")
            alg_id = self.java.names.get(part)
            if alg_id and alg_id not in ids:
                ids.append(alg_id)
        return ids

    def cipher(self, transformation: str) -> list[tuple[str, str]]:
        """"AES/CBC/PKCS5Padding" -> [(AES, ""), (CBC, "")]. A bare "AES" means ECB in Java."""
        parts = transformation.strip().upper().split("/")
        exact = parts[0] in self.java.names
        results = []
        for alg_id in self.lookup(parts[0]):
            alg = self.rules.algorithms[alg_id]
            is_block_cipher = alg.primitive == "block-cipher" and alg.mode is None
            if not (is_block_cipher and exact):
                results.append((alg_id, ""))
            elif len(parts) == 1:
                results += [(alg_id, ""), ("ECB", "no mode given: Java defaults to ECB")]
            else:
                mode_id = self.java.modes.get(re.sub(r"\d+$", "", parts[1]))
                if mode_id in ("AES_GCM", "AES_AEAD_OTHER") and alg_id == "AES":
                    results.append((mode_id, ""))
                else:
                    results.append((alg_id, ""))
                    if mode_id:
                        results.append((mode_id, ""))
        return results

    # -- the passes

    def scan(self) -> list[Finding]:
        pbkdf2_iterations = self._pbe_iterations()
        key_pair_vars: dict[str, str] = {}

        for m in GET_INSTANCE.finditer(self.masked):
            cls, token = m.group(1), m.group(2)
            name = self.string_value(token, m.span(2))
            if name is None:
                continue
            symbol = f'{cls}.getInstance("{name}")'
            results = self.cipher(name) if cls == "Cipher" else [(a, "") for a in self.lookup(name)]
            for alg_id, detail in results:
                if alg_id == "PBKDF2" and pbkdf2_iterations and self.java.pbkdf2:
                    count = min(pbkdf2_iterations)
                    rule = self.java.pbkdf2
                    alg_id = rule["below"] if count < rule["min"] else rule["otherwise"]
                    detail = f"iterations={count:,} (from PBEKeySpec)"
                self.report(m.start(), alg_id, symbol, detail)
            if cls == "KeyPairGenerator" and results:
                before = self.masked[self.line_starts[self.line_of(m.start()) - 1]:m.start()]
                var = ASSIGNED_TO.search(before)
                if var:
                    key_pair_vars[var.group(1)] = results[0][0]

        for m in SECRET_KEY_SPEC.finditer(self.masked):
            name = self.string_value(m.group(1), m.span(1))
            for alg_id in self.lookup(name or ""):
                self.report(m.start(), alg_id, f'new SecretKeySpec(..., "{name}")')

        self._key_sizes(key_pair_vars)
        self._insecure_random()
        self._enabled_protocols()
        for pattern, alg_id in self.java.patterns:
            for m in pattern.finditer(self.masked):
                symbol = " ".join(m.group(0).split())
                self.report(m.start(), alg_id, symbol[:60])
        return sorted(self.findings, key=lambda f: (f.line, f.algorithm.id))

    def _key_size_finding(self, offset: int, alg_id: str, bits: int | None, symbol: str) -> None:
        rule = self.java.key_size.get(alg_id)
        if bits is None or rule is None:
            return
        minimum, below = rule
        self.report(offset, below if bits < minimum else alg_id, symbol, f"key_size={bits:,}")

    def _key_sizes(self, key_pair_vars: dict[str, str]) -> None:
        for m in INITIALIZE.finditer(self.masked):
            alg_id = key_pair_vars.get(m.group(1))
            if alg_id:
                self._key_size_finding(m.start(), alg_id, self.int_value(m.group(2)),
                                       f"{m.group(1)}.initialize({m.group(2)})")
        for m in RSA_SPEC.finditer(self.masked):
            self._key_size_finding(m.start(), "RSA", self.int_value(m.group(1)),
                                   f"new RSAKeyGenParameterSpec({m.group(1)}, ...)")

    def _pbe_iterations(self) -> list[int]:
        counts = []
        for m in PBE_KEY_SPEC.finditer(self.masked):
            args = _split_args(self.masked, m.end() - 1)
            if len(args) >= 3:
                token = self.masked[args[2][0]:args[2][1]].strip()
                value = self.int_value(token) if re.fullmatch(INT_OR_NAME, token) else None
                if value is not None:
                    counts.append(value)
        return counts

    def _insecure_random(self) -> None:
        patterns = list(INSECURE_RANDOM)
        for var in {m.group(1) for m in RANDOM_VAR.finditer(self.masked)}:
            patterns.append(re.compile(rf"\b{re.escape(var)}\s*\.\s*(?:next\w*|ints|longs|doubles)\s*\("))
        for pattern in patterns:
            for m in pattern.finditer(self.masked):
                if self.in_secret_context(m.start()):
                    self.report(m.start(), "INSECURE_RANDOM", " ".join(m.group(0).split()).rstrip("("))

    def _enabled_protocols(self) -> None:
        for m in ENABLED_PROTOCOLS.finditer(self.masked):
            args = _split_args(self.masked, m.end() - 1)
            if not args:
                continue
            start, end = args[0][0], args[-1][1]
            for s in re.finditer(r'"[^"\n]*"', self.masked[start:end]):
                name = self._literal((start + s.start(), start + s.end()))
                for alg_id in self.lookup(name):
                    if alg_id.startswith("TLS"):
                        self.report(m.start(), alg_id, f'setEnabledProtocols("{name}")')


def scan_java_source(source: bytes | str, path: str, rules: Rules) -> list[Finding]:
    """Scan one Java file's source code."""
    if rules.java is None:
        return []
    text = source.decode("utf-8-sig", errors="replace") if isinstance(source, bytes) else source
    return _JavaScan(rules, path, text).scan()
