"""The rules file: valid as shipped, strict about mistakes, and easy to swap (crypto-agility)."""
import json

import pytest

from cryptoinv import load_rules
from cryptoinv.rules import DEFAULT_RULES, GRADES, RulesError, parse_rules
from cryptoinv.scanner import scan_path


def base():
    return json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))


def test_built_in_rules_load():
    rules = load_rules()
    assert len(rules.algorithms) > 40
    assert all(a.grade in GRADES for a in rules.algorithms.values())


@pytest.mark.parametrize("alg_id, grade", [
    ("MD5", "BROKEN"), ("SHA1", "BROKEN"), ("DES", "BROKEN"), ("RC4", "BROKEN"),
    ("RSA_WEAK", "BROKEN"), ("DSA_WEAK", "BROKEN"), ("UNSALTED_PASSWORD_HASH", "BROKEN"),
    ("TDES", "LEGACY"), ("RSA", "LEGACY"), ("ECC", "LEGACY"), ("ED25519", "LEGACY"),
    ("X25519", "LEGACY"), ("ECDH", "LEGACY"), ("DH", "LEGACY"), ("HMAC_SHA1", "LEGACY"),
    ("PBKDF2", "LEGACY"),
    ("AES", "CURRENT"), ("AES_GCM", "CURRENT"), ("CHACHA20_POLY1305", "CURRENT"),
    ("SHA256", "CURRENT"), ("SHA384", "CURRENT"), ("SHA512", "CURRENT"), ("SHA3", "CURRENT"),
    ("BLAKE2", "CURRENT"), ("HMAC", "CURRENT"), ("HKDF", "CURRENT"), ("SCRYPT", "CURRENT"),
    ("BCRYPT", "CURRENT"), ("ARGON2", "CURRENT"), ("MLKEM", "CURRENT"), ("MLDSA", "CURRENT"),
    ("SLHDSA", "CURRENT"), ("CSPRNG", "CURRENT"),
])
def test_grades_follow_the_broken_legacy_current_table(alg_id, grade):
    assert load_rules().algorithms[alg_id].grade == grade


def test_quantum_vulnerable_means_public_key_crypto_shor_breaks():
    vulnerable = {a.id for a in load_rules().algorithms.values() if a.quantum_vulnerable}
    assert vulnerable == {"RSA", "RSA_WEAK", "DSA", "DSA_WEAK", "DH", "DH_WEAK", "ECC", "ECDH",
                          "ED25519", "ED448", "X25519", "X448"}


def test_most_specific_detector_wins():
    rules = load_rules()
    assert rules.match("cryptography.hazmat.primitives.asymmetric.ec.ECDH").algorithm == "ECDH"
    assert rules.match("cryptography.hazmat.primitives.asymmetric.ec.SECP256R1").algorithm == "ECC"
    assert rules.match("random.SystemRandom").algorithm == "CSPRNG"
    assert rules.match("Cryptodome.Cipher.DES").algorithm == "DES"
    assert rules.match("hashlib") is None
    assert rules.match("hashlib.md5x") is None  # names must match whole parts


def test_hash_names_are_forgiving_about_spelling():
    rules = load_rules()
    assert rules.hash_by_name("SHA-256") == rules.hash_by_name("sha256") == "SHA256"


@pytest.mark.parametrize("break_it, message", [
    (lambda d: d["algorithms"]["MD5"].update(grade="MAYBE"), "grade must be one of"),
    (lambda d: d["detectors"].append({"match": "x.y", "algorithm": "NOPE"}), "unknown algorithm 'NOPE'"),
    (lambda d: d["detectors"].append({"match": "x.y", "algorith": "MD5"}), "unknown field"),
    (lambda d: d["algorithms"]["RSA"].update(pq_partner="MLKEMM"), "unknown algorithm 'MLKEMM'"),
    (lambda d: d.pop("detectors"), "missing the 'detectors' section"),
])
def test_mistakes_in_rules_are_caught(break_it, message):
    data = base()
    break_it(data)
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_unreadable_rules_file(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text("{ not json")
    with pytest.raises(RulesError, match="not valid JSON"):
        load_rules(bad)
    with pytest.raises(RulesError, match="can't read"):
        load_rules(tmp_path / "missing.json")


def test_custom_rules_change_grades_without_code_changes(tmp_path):
    """Crypto-agility: if SHA-256 were ever weakened, one edit to the rules file re-grades it."""
    data = base()
    data["algorithms"]["SHA256"]["grade"] = "LEGACY"
    custom = tmp_path / "rules.json"
    custom.write_text(json.dumps(data))
    target = tmp_path / "app.py"
    target.write_text("import hashlib\nhashlib.sha256(b'x')\n")
    assert scan_path(target).findings[0].grade == "CURRENT"
    assert scan_path(target, load_rules(custom)).findings[0].grade == "LEGACY"
