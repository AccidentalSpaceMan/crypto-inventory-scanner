"""Load and check the grading rules (rules.json).

The rules live in a data file, not in code, so grades can change without touching the scanner:
if a new attack breaks an algorithm tomorrow, you edit one line of JSON. That's crypto-agility.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

GRADES = ("BROKEN", "LEGACY", "CURRENT")  # worst first
DEFAULT_RULES = Path(__file__).with_name("rules.json")

_ALGORITHM_FIELDS = {"name", "grade", "primitive", "quantum_vulnerable", "why", "fix",
                     "fast_hash", "pq_partner"}
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
class Rules:
    version: str
    algorithms: dict[str, Algorithm]
    detectors: tuple[Detector, ...]  # most specific first
    hash_names: dict[str, str]       # normalised hashlib name -> algorithm id

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
    return Rules(version=str(data.get("rules_version", "unknown")), algorithms=algorithms,
                 detectors=tuple(detectors), hash_names=hash_names)
