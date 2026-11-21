"""Load and check the grading rules (rules.json).

The rules live in a data file, not in code, so grades can change without touching the scanner:
if a new attack breaks an algorithm tomorrow, you edit one line of JSON. That's crypto-agility.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

GRADES = ("BROKEN", "LEGACY", "CURRENT")  # worst first
DEFAULT_RULES = Path(__file__).with_name("rules.json")

_ALGORITHM_FIELDS = {"name", "grade", "primitive", "quantum_vulnerable", "why", "fix",
                     "fast_hash", "pq_partner", "mode"}
_DETECTOR_FIELDS = {"match", "algorithm", "calls_only", "secret_context", "threshold", "hash_arg"}
_THRESHOLD_FIELDS = {"call", "keyword", "position", "min", "below", "otherwise"}
_HASH_ARG_FIELDS = {"call", "keyword", "position", "variants"}


class RulesError(ValueError):
    """The rules file is missing, isn't valid JSON, or contains a mistake."""


@dataclass(frozen=True)
class Algorithm:
    """One graded algorithm, e.g. MD5 (BROKEN) or ML-KEM (CURRENT)."""
    id: str
    name: str
    grade: str                # BROKEN / LEGACY / CURRENT
    primitive: str            # CycloneDX primitive name: hash, block-cipher, signature, kem, ...
    quantum_vulnerable: bool  # broken by Shor's algorithm on a large quantum computer
    why: str
    fix: str
    fast_hash: bool = False   # a general-purpose hash (fine for data, wrong for passwords)
    pq_partner: str | None = None  # the post-quantum algorithm that replaces it
    mode: str | None = None   # cipher mode for the CBOM (ecb, cbc, gcm, ...)


@dataclass(frozen=True)
class Detector:
    """A code pattern that reveals an algorithm.

    `match` is a full dotted name as Python would resolve it after imports, e.g.
    "hashlib.md5". It also matches anything inside it ("...asymmetric.rsa" matches
    "...asymmetric.rsa.generate_private_key"). A leading "*." matches the end of a name
    instead, e.g. "*.MODE_ECB".
    """
    match: str
    algorithm: str
    calls_only: bool = False      # only report when called (not on import lines)
    secret_context: bool = False  # only report when the code looks like it's making a secret
    threshold: dict | None = None  # check a numeric argument, e.g. RSA key_size < 2048
    hash_arg: dict | None = None   # read which hash an HMAC/KDF uses, e.g. HMAC with SHA-1

    def matches(self, dotted: str) -> bool:
        if self.match.startswith("*."):
            return dotted.endswith(self.match[1:])
        return dotted == self.match or dotted.startswith(self.match + ".")


def _norm_hash_name(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")


@dataclass(frozen=True)
class JavaRules:
    """How to read Java's algorithm-name strings, e.g. "AES/GCM/NoPadding" or "SHA256withRSA"."""
    names: dict[str, str]                  # upper-case Java name -> algorithm id
    modes: dict[str, str]                  # upper-case cipher mode -> algorithm id
    key_size: dict[str, tuple[int, str]]   # algorithm id -> (minimum bits, id to use below it)
    pbkdf2: dict                           # {"min", "below", "otherwise"}
    patterns: tuple[tuple[re.Pattern, str], ...]  # library calls found by regex


@dataclass(frozen=True)
class JsRules:
    """How to read JavaScript/TypeScript algorithm names. Each table maps a name to algorithm ids."""
    node_names: dict[str, tuple[str, ...]]    # Node crypto: hashes, key types ("sha1", "rsa", ...)
    ciphers: dict[str, tuple[str, ...]]       # OpenSSL cipher families ("aes", "des-ede3", ...)
    cipher_modes: dict[str, tuple[str, ...]]  # "cbc", "gcm", ...
    webcrypto: dict[str, tuple[str, ...]]     # browser WebCrypto names ("AES-GCM", ...)
    jwt: dict[str, tuple[str, ...]]           # JSON Web Token algorithms ("HS256", "none", ...)
    tls: dict[str, tuple[str, ...]]           # TLS versions / protocol methods
    modules: dict[str, tuple[str, ...]]       # npm modules whose import reveals an algorithm
    cipher_default_modes: dict[str, str]      # mode OpenSSL uses when a name has none
    dh_groups: dict[str, int]                 # named Diffie-Hellman groups -> bits
    key_size: dict[str, tuple[int, str]]
    pbkdf2: dict
    patterns: tuple[tuple[re.Pattern, str], ...]


@dataclass(frozen=True)
class GoRules:
    """How to read Go code, where crypto is organised by import path."""
    packages: dict[str, tuple[str, ...]]  # import path -> ids (also covers sub-packages)
    symbols: dict[str, tuple[str, ...]]   # "path.Name" -> ids, overriding the package
    calls: dict[str, dict]                # "path.Func" -> argument positions holding details
    secret_context: frozenset[str]        # packages only reported in secret-looking code
    tls_suite_parts: dict[str, str]       # word in a TLS cipher-suite name -> id
    key_size: dict[str, tuple[int, str]]
    pbkdf2: dict
    patterns: tuple[tuple[re.Pattern, str], ...]

    def package_ids(self, path: str) -> tuple[str, ...]:
        """Ids for an import path, falling back to its parent paths (circl/kem/mlkem/mlkem768)."""
        while path:
            if path in self.packages:
                return self.packages[path]
            path = path.rpartition("/")[0]
        return ()


@dataclass(frozen=True)
class Rules:
    version: str
    algorithms: dict[str, Algorithm]
    detectors: tuple[Detector, ...]  # most specific first
    hash_names: dict[str, str]       # normalised hashlib name -> algorithm id
    java: JavaRules | None = None
    javascript: JsRules | None = None
    go: GoRules | None = None

    def match(self, dotted: str) -> Detector | None:
        """Return the most specific detector for a dotted name, or None."""
        for detector in self.detectors:
            if detector.matches(dotted):
                return detector
        return None

    def hash_by_name(self, name: str) -> str | None:
        """Map a hash name string like "sha256" or "SHA-1" to an algorithm id."""
        return self.hash_names.get(_norm_hash_name(name))


def load_rules(path: str | Path | None = None) -> Rules:
    """Load rules from a JSON file (the built-in rules.json by default)."""
    path = Path(path) if path else DEFAULT_RULES
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise RulesError(f"can't read rules file {path}: {e.strerror or e}") from e
    except json.JSONDecodeError as e:
        raise RulesError(f"rules file {path} is not valid JSON: {e}") from e
    return parse_rules(data)


def _check_keys(where: str, given: dict, allowed: set[str]) -> None:
    unknown = set(given) - allowed
    if unknown:
        raise RulesError(f"{where}: unknown field(s) {sorted(unknown)}")


def parse_rules(data: dict) -> Rules:
    """Build Rules from already-parsed JSON, checking every reference."""
    if not isinstance(data, dict):
        raise RulesError("rules must be a JSON object")
    try:
        raw_algorithms = data["algorithms"]
        raw_detectors = data["detectors"]
    except KeyError as e:
        raise RulesError(f"rules file is missing the {e.args[0]!r} section") from e

    algorithms: dict[str, Algorithm] = {}
    for alg_id, spec in raw_algorithms.items():
        where = f"algorithm {alg_id}"
        _check_keys(where, spec, _ALGORITHM_FIELDS)
        try:
            alg = Algorithm(id=alg_id, **spec)
        except TypeError as e:
            raise RulesError(f"{where}: {e}") from e
        if alg.grade not in GRADES:
            raise RulesError(f"{where}: grade must be one of {', '.join(GRADES)}, not {alg.grade!r}")
        algorithms[alg_id] = alg

    def need(where: str, alg_id) -> None:
        if alg_id not in algorithms:
            raise RulesError(f"{where}: refers to unknown algorithm {alg_id!r}")

    for alg in algorithms.values():
        if alg.pq_partner:
            need(f"algorithm {alg.id} pq_partner", alg.pq_partner)

    hash_names = {}
    for name, alg_id in data.get("hash_names", {}).items():
        need(f"hash_names[{name!r}]", alg_id)
        hash_names[_norm_hash_name(name)] = alg_id

    detectors = []
    for i, spec in enumerate(raw_detectors):
        where = f"detector #{i + 1} ({spec.get('match', '?')})"
        _check_keys(where, spec, _DETECTOR_FIELDS)
        if "match" not in spec or "algorithm" not in spec:
            raise RulesError(f"{where}: needs both 'match' and 'algorithm'")
        need(where, spec["algorithm"])
        if spec.get("threshold"):
            th = spec["threshold"]
            _check_keys(f"{where} threshold", th, _THRESHOLD_FIELDS)
            if "min" not in th or "below" not in th or ("keyword" not in th and "position" not in th):
                raise RulesError(f"{where} threshold: needs 'min', 'below' and a keyword or position")
            need(f"{where} threshold", th["below"])
            if "otherwise" in th:
                need(f"{where} threshold", th["otherwise"])
        if spec.get("hash_arg"):
            ha = spec["hash_arg"]
            _check_keys(f"{where} hash_arg", ha, _HASH_ARG_FIELDS)
            for hash_id, variant in ha.get("variants", {}).items():
                need(f"{where} hash_arg variants", hash_id)
                need(f"{where} hash_arg variants", variant)
        detectors.append(Detector(**spec))
        # PyCryptodome ships under two names: Crypto and Cryptodome. Match both.
        if spec["match"].startswith("Crypto."):
            detectors.append(Detector(**{**spec, "match": "Cryptodome." + spec["match"][len("Crypto."):]}))

    # Most specific first: "*.SUFFIX" patterns, then longer names before shorter ones,
    # so "...asymmetric.ec.ECDH" wins over "...asymmetric.ec".
    detectors.sort(key=lambda d: (not d.match.startswith("*."), -len(d.match)))
    java = _parse_java(data["java"], need) if "java" in data else None
    javascript = _parse_js(data["javascript"], need) if "javascript" in data else None
    go = _parse_go(data["go"], need) if "go" in data else None
    return Rules(version=str(data.get("rules_version", "unknown")), algorithms=algorithms,
                 detectors=tuple(detectors), hash_names=hash_names, java=java,
                 javascript=javascript, go=go)


def _parse_key_size(where: str, spec: dict, need) -> dict[str, tuple[int, str]]:
    key_size = {}
    for alg_id, rule in spec.items():
        need(f"{where} key_size", alg_id)
        if "min" not in rule or "below" not in rule:
            raise RulesError(f"{where} key_size[{alg_id!r}]: needs 'min' and 'below'")
        need(f"{where} key_size[{alg_id!r}]", rule["below"])
        key_size[alg_id] = (int(rule["min"]), rule["below"])
    return key_size


def _parse_pbkdf2(where: str, pbkdf2: dict, need) -> dict:
    if pbkdf2:
        if not {"min", "below", "otherwise"} <= set(pbkdf2):
            raise RulesError(f"{where} pbkdf2: needs 'min', 'below' and 'otherwise'")
        need(f"{where} pbkdf2", pbkdf2["below"])
        need(f"{where} pbkdf2", pbkdf2["otherwise"])
    return pbkdf2


def _parse_patterns(where: str, specs: list, need) -> tuple[tuple[re.Pattern, str], ...]:
    patterns = []
    for i, p in enumerate(specs):
        here = f"{where} pattern #{i + 1}"
        _check_keys(here, p, {"regex", "algorithm"})
        need(here, p.get("algorithm"))
        try:
            patterns.append((re.compile(p["regex"]), p["algorithm"]))
        except (re.error, KeyError) as e:
            raise RulesError(f"{here}: bad or missing regex: {e}") from e
    return tuple(patterns)


def _parse_java(spec: dict, need) -> JavaRules:
    _check_keys("java", spec, {"_comment", "names", "modes", "key_size", "pbkdf2", "patterns"})
    names, modes = {}, {}
    for name, alg_id in spec.get("names", {}).items():
        need(f"java names[{name!r}]", alg_id)
        names[name.upper()] = alg_id
    for mode, alg_id in spec.get("modes", {}).items():
        need(f"java modes[{mode!r}]", alg_id)
        modes[mode.upper()] = alg_id
    return JavaRules(names=names, modes=modes,
                     key_size=_parse_key_size("java", spec.get("key_size", {}), need),
                     pbkdf2=_parse_pbkdf2("java", spec.get("pbkdf2", {}), need),
                     patterns=_parse_patterns("java", spec.get("patterns", []), need))


_JS_TABLES = ("node_names", "ciphers", "cipher_modes", "webcrypto", "jwt", "tls", "modules")


def _parse_js(spec: dict, need) -> JsRules:
    _check_keys("javascript", spec, {"_comment", "_cipher_default_modes_comment", *_JS_TABLES,
                                     "cipher_default_modes", "dh_groups", "key_size", "pbkdf2",
                                     "patterns"})
    tables = {}
    for table in _JS_TABLES:
        parsed = {}
        for name, value in spec.get(table, {}).items():
            ids = (value,) if isinstance(value, str) else tuple(value)
            for alg_id in ids:
                need(f"javascript {table}[{name!r}]", alg_id)
            # npm module names are exact; every other table is case-insensitive
            parsed[name if table == "modules" else name.upper()] = ids
        tables[table] = parsed
    default_modes = {k.lower(): v.lower() for k, v in spec.get("cipher_default_modes", {}).items()}
    for base, mode in default_modes.items():
        if mode.upper() not in tables["cipher_modes"]:
            raise RulesError(f"javascript cipher_default_modes[{base!r}]: unknown mode {mode!r}")
    return JsRules(**tables, cipher_default_modes=default_modes,
                   dh_groups={k.lower(): int(v) for k, v in spec.get("dh_groups", {}).items()},
                   key_size=_parse_key_size("javascript", spec.get("key_size", {}), need),
                   pbkdf2=_parse_pbkdf2("javascript", spec.get("pbkdf2", {}), need),
                   patterns=_parse_patterns("javascript", spec.get("patterns", []), need))


_GO_CALL_FIELDS = {"algorithm", "hash_arg", "variants", "iterations_arg", "key_size_arg"}


def _id_table(where: str, table: dict, need) -> dict[str, tuple[str, ...]]:
    parsed = {}
    for name, value in table.items():
        ids = (value,) if isinstance(value, str) else tuple(value)
        for alg_id in ids:
            need(f"{where}[{name!r}]", alg_id)
        parsed[name] = ids
    return parsed


def _parse_go(spec: dict, need) -> GoRules:
    _check_keys("go", spec, {"_comment", "_secret_context_comment", "_tls_suite_parts_comment",
                             "packages", "symbols", "calls", "secret_context", "tls_suite_parts",
                             "key_size", "pbkdf2", "patterns"})
    packages = _id_table("go packages", spec.get("packages", {}), need)
    calls = {}
    for name, call in spec.get("calls", {}).items():
        where = f"go calls[{name!r}]"
        _check_keys(where, call, _GO_CALL_FIELDS)
        need(where, call.get("algorithm"))
        for hash_id, variant in call.get("variants", {}).items():
            need(f"{where} variants", hash_id)
            need(f"{where} variants", variant)
        calls[name] = call
    secret = frozenset(spec.get("secret_context", []))
    for path in secret:
        if path not in packages:
            raise RulesError(f"go secret_context: {path!r} is not in go packages")
    suite_parts = {}
    for part, alg_id in spec.get("tls_suite_parts", {}).items():
        need(f"go tls_suite_parts[{part!r}]", alg_id)
        suite_parts[part.upper()] = alg_id
    return GoRules(packages=packages, symbols=_id_table("go symbols", spec.get("symbols", {}), need),
                   calls=calls, secret_context=secret, tls_suite_parts=suite_parts,
                   key_size=_parse_key_size("go", spec.get("key_size", {}), need),
                   pbkdf2=_parse_pbkdf2("go", spec.get("pbkdf2", {}), need),
                   patterns=_parse_patterns("go", spec.get("patterns", []), need))
