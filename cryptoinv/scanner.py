"""Find cryptography in Python source code.

The scanner never runs the code it scans. It parses each file into a syntax tree with
Python's built-in `ast` module (the same first step Python itself takes) and walks the tree
looking for imports and calls that match the detectors in rules.json.

Why a syntax tree instead of searching text? Text search can't tell `hashlib.md5(data)` from
a comment that mentions md5, or know that `import hashlib as h` makes `h.md5` mean the same
thing. The tree knows exactly which names were imported and what each call's arguments are,
so it can also read details like an RSA key size or a PBKDF2 iteration count.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .rules import Algorithm, Detector, Rules, load_rules

# Folders that hold other people's code or generated files, not the project itself.
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules",
             "site-packages", ".tox", ".nox", ".mypy_cache", ".pytest_cache", "build", "dist",
             "target", ".gradle", ".idea"}

# Words in a variable or function name that suggest a value is a secret.
SECRET_WORDS = {"key", "keys", "secret", "secrets", "token", "tokens", "password", "passwords",
                "passwd", "pwd", "passphrase", "nonce", "salt", "iv", "otp", "pin", "session",
                "sessionid", "auth", "credential", "credentials", "seed", "apikey"}
PASSWORD_WORDS = {"password", "passwords", "passwd", "pwd", "passphrase"}

_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def _words(name: str) -> list[str]:
    """Split an identifier into lowercase words: "apiKey" / "API_KEY" -> ["api", "key"]."""
    return [w.lower() for w in _WORD_RE.findall(name)]


@dataclass(frozen=True)
class Finding:
    """One place in the code where an algorithm is used."""
    path: str        # file, relative to the scanned folder
    line: int
    algorithm: Algorithm
    symbol: str      # what matched, e.g. "hashlib.md5"
    detail: str      # extra facts read from the code, e.g. "key_size=1024"
    code: str        # the source line, for context

    @property
    def grade(self) -> str:
        return self.algorithm.grade


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (file, why it was skipped)
    rules: Rules | None = None  # the rules used, so reports can look up algorithm names
    languages: dict[str, int] = field(default_factory=dict)  # files scanned per language


# ------------------------------------------------------------------ small AST helpers

def _get_arg(call: ast.Call, position: int | None, keyword: str | None) -> ast.expr | None:
    """Return the argument passed by keyword or at a position, if it can be found."""
    if keyword:
        for kw in call.keywords:
            if kw.arg == keyword:
                return kw.value
    if position is not None and position < len(call.args):
        if not any(isinstance(a, ast.Starred) for a in call.args[:position + 1]):
            return call.args[position]
    return None


def _int_value(node: ast.expr | None) -> int | None:
    """Evaluate a literal whole number such as 2048, 600_000 or 2**11; None if not literal."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = _int_value(node.left), _int_value(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Pow) and 0 <= right <= 64:
            return left ** right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.LShift) and 0 <= right <= 64:
            return left << right
    return None


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _names_in(node: ast.AST) -> list[str]:
    """All variable names, attribute names and string keys inside a piece of code."""
    names = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.append(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and len(sub.value) < 40:
            names.append(sub.value)
    return names


def _mentions(node: ast.AST, words: set[str]) -> bool:
    """True if a variable or attribute name inside `node` contains one of `words`."""
    for sub in ast.walk(node):
        name = sub.id if isinstance(sub, ast.Name) else sub.attr if isinstance(sub, ast.Attribute) else None
        if name and any(w in words for w in _words(name)):
            return True
    return False


def _applies(option: dict, last_name: str) -> bool:
    """Does a threshold / hash_arg option apply to a call of `last_name`?"""
    calls = option.get("call")
    if not calls:
        return True
    return last_name in ([calls] if isinstance(calls, str) else calls)


# ------------------------------------------------------------------ the tree walker

class _Visitor(ast.NodeVisitor):
    """Walks one file's syntax tree and records findings."""

    def __init__(self, rules: Rules, path: str, lines: list[str]):
        self.rules = rules
        self.path = path
        self.lines = lines
        self.aliases: dict[str, str] = {}   # local name -> full dotted name it was imported as
        self.context: list[list[str]] = []  # names around the current code (function, variable)
        self.findings: list[Finding] = []
        self._seen: set[tuple[int, str]] = set()

    # -- imports: learn what each local name really refers to

    def collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name          # import hashlib as h
                    else:
                        top = a.name.split(".")[0]                # import os.path binds "os"
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":                             # from hashlib import md5
                        self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def dotted(self, node: ast.AST) -> str | None:
        """Turn `h.md5` into "hashlib.md5" using the imports; None if not an imported name."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id not in self.aliases:
            return None
        return ".".join([self.aliases[node.id], *reversed(parts)])

    # -- recording

    def report(self, node: ast.AST, alg_id: str, symbol: str, detail: str = "") -> None:
        line = getattr(node, "lineno", 0)
        if (line, alg_id) in self._seen:  # one finding per algorithm per line
            return
        self._seen.add((line, alg_id))
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(self.path, line, self.rules.algorithms[alg_id], symbol, detail, code))

    def in_secret_context(self) -> bool:
        return any(w in SECRET_WORDS for names in self.context for n in names for w in _words(n))

    def check_reference(self, dotted: str, node: ast.AST) -> None:
        """An import or a bare use of a name (not a call)."""
        detector = self.rules.match(dotted)
        if detector is None or detector.calls_only:
            return
        if detector.secret_context and not self.in_secret_context():
            return
        self.report(node, detector.algorithm, dotted)

    # -- context tracking (used to decide whether `random` is making a secret)

    def visit_FunctionDef(self, node):
        self.context.append([node.name])
        self.generic_visit(node)
        self.context.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _visit_assignment(self, targets: list[ast.expr], value: ast.expr | None) -> None:
        for target in targets:
            if isinstance(target, ast.Attribute) and target.attr == "check_hostname" and _is_false(value):
                self.report(target, "TLS_NO_VERIFY", "check_hostname = False")
            self.visit(target)
        if value is not None:
            self.context.append([n for t in targets for n in _names_in(t)])
            self.visit(value)
            self.context.pop()

    def visit_Assign(self, node):
        self._visit_assignment(node.targets, node.value)

    def visit_AnnAssign(self, node):
        self.visit(node.annotation)
        self._visit_assignment([node.target], node.value)

    def visit_AugAssign(self, node):
        self._visit_assignment([node.target], node.value)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if key is not None:
                self.visit(key)
            self.context.append(_names_in(key) if key is not None else [])
            self.visit(value)
            self.context.pop()

    # -- imports and names

    def visit_Import(self, node):
        for a in node.names:
            self.check_reference(a.name, node)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    self.check_reference(f"{node.module}.{a.name}", node)

    def visit_Name(self, node):
        dotted = self.dotted(node)
        if dotted:
            self.check_reference(dotted, node)

    def visit_Attribute(self, node):
        dotted = self.dotted(node)
        if dotted is None:
            self.generic_visit(node)  # e.g. foo().bar: look inside foo()
        else:
            self.check_reference(dotted, node)

    # -- calls: where the interesting details (key sizes, hashes, iterations) live

    def visit_Call(self, node):
        dotted = self.dotted(node.func)
        consumed: set[int] = set()  # arguments already accounted for (e.g. HMAC's hash)
        if dotted is None:
            self.visit(node.func)
        elif dotted == "hashlib.new":
            consumed = self._hashlib_new(node)
        else:
            detector = self.rules.match(dotted)
            if detector:
                consumed = self._check_call(detector, dotted, node)

        for kw in node.keywords:
            if kw.arg == "verify" and _is_false(kw.value):  # requests.get(url, verify=False)
                self.report(kw.value, "TLS_NO_VERIFY", "verify=False")

        for arg in node.args:
            if id(arg) not in consumed:
                self.visit(arg)
        for kw in node.keywords:
            if id(kw.value) not in consumed:
                self.context.append([kw.arg] if kw.arg else [])
                self.visit(kw.value)
                self.context.pop()

    def _check_call(self, detector: Detector, dotted: str, node: ast.Call) -> set[int]:
        if detector.secret_context and not self.in_secret_context():
            return set()
        alg_id, details, consumed = detector.algorithm, [], set()
        last_name = dotted.rsplit(".", 1)[-1]

        th = detector.threshold
        if th and _applies(th, last_name):
            value = _int_value(_get_arg(node, th.get("position"), th.get("keyword")))
            if value is not None:
                details.append(f"{th.get('keyword', 'size')}={value:,}")
                alg_id = th["below"] if value < th["min"] else th.get("otherwise", alg_id)

        ha = detector.hash_arg
        if ha and _applies(ha, last_name):
            arg = _get_arg(node, ha.get("position"), ha.get("keyword"))
            hash_id = self._hash_of(arg)
            if hash_id:
                consumed.add(id(arg))
                details.append(f"hash: {self.rules.algorithms[hash_id].name}")
                alg_id = ha.get("variants", {}).get(hash_id, alg_id)

        self._finish(node, alg_id, dotted, details)
        return consumed

    def _hashlib_new(self, node: ast.Call) -> set[int]:
        """hashlib.new("md5", data): the algorithm is a string argument."""
        arg = _get_arg(node, 0, "name")
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            return set()
        hash_id = self.rules.hash_by_name(arg.value)
        if hash_id:
            self._finish(node, hash_id, f'hashlib.new("{arg.value}")', [])
        return {id(arg)}

    def _hash_of(self, arg: ast.expr | None) -> str | None:
        """Which hash does this argument name? Handles "sha1", hashlib.sha1 and hashes.SHA1()."""
        if arg is None:
            return None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return self.rules.hash_by_name(arg.value)
        dotted = self.dotted(arg.func if isinstance(arg, ast.Call) else arg)
        detector = self.rules.match(dotted) if dotted else None
        if detector and self.rules.algorithms[detector.algorithm].fast_hash:
            return detector.algorithm
        return None

    def _finish(self, node: ast.Call, alg_id: str, symbol: str, details: list[str]) -> None:
        # A fast hash like SHA-256 applied to something called "password" is a password hash.
        if self.rules.algorithms[alg_id].fast_hash and _mentions(node, PASSWORD_WORDS):
            alg_id = "UNSALTED_PASSWORD_HASH"
        if _is_false(_get_arg(node, None, "usedforsecurity")):
            details.append("usedforsecurity=False")
        self.report(node, alg_id, symbol, ", ".join(details))


# ------------------------------------------------------------------ public API

def scan_source(source: bytes | str, path: str, rules: Rules) -> list[Finding]:
    """Scan one file's source code. Raises SyntaxError/ValueError if it can't be parsed."""
    tree = ast.parse(source, filename=path)
    text = source.decode("utf-8-sig", errors="replace") if isinstance(source, bytes) else source
    visitor = _Visitor(rules, path, text.splitlines())
    visitor.collect_imports(tree)
    visitor.visit(tree)
    return visitor.findings


LANGUAGES = {".py": "Python", ".java": "Java"}


def iter_source_files(root: Path):
    """Yield supported source files under root (or root itself), skipping SKIP_DIRS."""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if Path(name).suffix in LANGUAGES:
                yield Path(dirpath) / name


def scan_path(path: str | Path, rules: Rules | None = None) -> ScanResult:
    """Scan a file or a folder of Python and Java code and return every finding."""
    from .java_scanner import scan_java_source  # imported here: it builds on this module

    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"{path} does not exist")
    rules = rules or load_rules()
    result = ScanResult(root=str(path), rules=rules)
    for file in iter_source_files(root):
        language = LANGUAGES.get(file.suffix)
        if language is None:
            result.errors.append((file.as_posix(), "not a supported file type (.py or .java)"))
            continue
        display = file.as_posix() if root.is_file() else file.relative_to(root).as_posix()
        scan = scan_source if language == "Python" else scan_java_source
        try:
            source = file.read_bytes()
            result.findings.extend(scan(source, display, rules))
        except SyntaxError as e:
            result.errors.append((display, f"could not parse line {e.lineno}: {e.msg}"))
            continue
        except (ValueError, RecursionError, OSError) as e:
            result.errors.append((display, f"could not read: {e}"))
            continue
        result.files_scanned += 1
        result.languages[language] = result.languages.get(language, 0) + 1
    result.findings.sort(key=lambda f: (f.path, f.line, f.algorithm.id))
    return result
