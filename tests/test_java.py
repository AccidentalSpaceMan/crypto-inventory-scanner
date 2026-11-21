"""Java scanning beyond the sample files: masking, name parsing, edge cases."""
import json
from pathlib import Path

import pytest

from cryptoinv import load_rules
from cryptoinv.cbom import build_cbom
from cryptoinv.cli import main
from cryptoinv.java_scanner import mask, scan_java_source
from cryptoinv.rules import DEFAULT_RULES, RulesError, parse_rules
from cryptoinv.scanner import scan_path

RULES = load_rules()
JAVA_SAMPLES = Path(__file__).parent / "samples_java"


def ids(java: str) -> list[str]:
    return [f.algorithm.id for f in scan_java_source(java, "X.java", RULES)]


# -- masking comments and strings

def test_mask_keeps_length_and_line_breaks():
    src = 'a // c "x"\nb /* multi\nline */ "str" \'"\' c'
    no_comments, masked = mask(src)
    assert len(no_comments) == len(masked) == len(src)
    assert no_comments.count("\n") == masked.count("\n") == src.count("\n")
    assert '"str"' in no_comments and '"   "' in masked   # string contents blanked, quotes kept
    assert "multi" not in no_comments and "//" not in no_comments


def test_char_literal_quote_does_not_start_a_string():
    assert ids("char q = '\"';\nMessageDigest.getInstance(\"MD5\");\n") == ["MD5"]


def test_escaped_quote_inside_string():
    assert ids('String s = "say \\"hi\\" MessageDigest.getInstance(\\"MD5\\")";\n') == []


def test_text_blocks_are_strings():
    assert ids('String s = """\n  Cipher.getInstance("DES")\n  """;\n') == []


# -- algorithm names

@pytest.mark.parametrize("name, expected", [
    ("sha-256", ["SHA256"]),                 # case-insensitive
    ("SHA512withRSA/PSS", ["SHA512", "RSA"]),
    ("SHA256withECDSAinP1363Format", ["SHA256", "ECC"]),
    ("SHA256withRSAandMGF1", ["SHA256", "RSA"]),
    ("RSASSA-PSS", ["RSA"]),
    ("NoSuchAlgorithm", []),
])
def test_signature_names(name, expected):
    assert sorted(ids(f'Signature.getInstance("{name}");')) == sorted(expected)


def test_unknown_constant_is_skipped_safely():
    assert ids("Cipher.getInstance(Config.ALGORITHM);") == []


def test_multiline_trust_all_manager():
    java = ("public void checkServerTrusted(X509Certificate[] c, String a)\n"
            "        throws CertificateException {\n"
            "    // trust everyone\n"
            "}\n")
    assert ids(java) == ["TLS_NO_VERIFY"]


def test_real_trust_manager_is_not_flagged():
    java = "public void checkServerTrusted(X509Certificate[] c, String a) { delegate.checkServerTrusted(c, a); }"
    assert ids(java) == []


def test_strong_pbkdf2_iterations():
    java = ('static final int ITERATIONS = 600_000;\n'
            'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");\n'
            'new PBEKeySpec(pw, salt, ITERATIONS, 256);\n')
    [f] = scan_java_source(java, "X.java", RULES)
    assert f.algorithm.id == "PBKDF2_STRONG" and f.detail == "iterations=600,000 (from PBEKeySpec)"


def test_random_variable_in_secret_context():
    java = ("Random r = new Random();\n"
            "String apiKey = Long.toHexString(r.nextLong());\n"
            "int dice = r.nextInt(6);\n")
    found = scan_java_source(java, "X.java", RULES)
    assert [(f.line, f.algorithm.id) for f in found] == [(2, "INSECURE_RANDOM")]


def test_details_and_line_numbers():
    by_line = {f.line: f for f in scan_path(JAVA_SAMPLES / "PublicKey.java").findings
               if f.algorithm.id == "RSA_WEAK"}
    assert by_line[16].detail == "key_size=1,024"
    assert by_line[16].symbol == "kpg.initialize(SMALL)"
    ecb = next(f for f in scan_path(JAVA_SAMPLES / "Ciphers.java").findings if f.line == 14 and f.algorithm.id == "ECB")
    assert ecb.detail == "no mode given: Java defaults to ECB"


# -- folders, report and CBOM

def test_mixed_language_folder(tmp_path, capsys):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.java").write_text('class App { void f() throws Exception { Cipher.getInstance("DES"); } }\n')
    (tmp_path / "target").mkdir()   # Maven build output: skipped
    (tmp_path / "target" / "Gen.java").write_text('MessageDigest.getInstance("SHA-1");\n')
    result = scan_path(tmp_path)
    assert result.languages == {"Python": 1, "Java": 1}
    assert {(f.path, f.algorithm.id) for f in result.findings} == {
        ("app.py", "MD5"), ("src/App.java", "DES"), ("src/App.java", "ECB")}
    main(["scan", str(tmp_path), "--no-color"])
    assert "2 file(s) scanned (1 Java, 1 Python)" in capsys.readouterr().out


def test_java_findings_make_a_valid_cbom():
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    cbom = build_cbom(scan_path(JAVA_SAMPLES))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(cbom)) is None
    locations = {o["location"] for c in cbom["components"] for o in c["evidence"]["occurrences"]}
    assert locations == {p.name for p in JAVA_SAMPLES.glob("*.java")}


def test_unsupported_single_file(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("MD5")
    result = scan_path(notes)
    assert result.files_scanned == 0 and len(result.errors) == 1


# -- rules validation for the java section

@pytest.mark.parametrize("break_it, message", [
    (lambda j: j["names"].update(FOO="NOPE"), "unknown algorithm 'NOPE'"),
    (lambda j: j["patterns"].append({"regex": "(", "algorithm": "MD5"}), "bad or missing regex"),
    (lambda j: j["key_size"].update(RSA={"min": 2048}), "needs 'min' and 'below'"),
    (lambda j: j.update(extra=1), "unknown field"),
])
def test_mistakes_in_java_rules_are_caught(break_it, message):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    break_it(data["java"])
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_rules_without_java_section_skip_java(tmp_path):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    del data["java"]
    rules = parse_rules(data)
    assert scan_path(JAVA_SAMPLES, rules).findings == []
