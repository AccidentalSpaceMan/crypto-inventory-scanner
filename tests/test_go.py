"""Go scanning beyond the sample files."""
import json
from pathlib import Path

import pytest

from cryptoinv import load_rules
from cryptoinv.cbom import build_cbom
from cryptoinv.cli import main
from cryptoinv.go_scanner import scan_go_source
from cryptoinv.rules import DEFAULT_RULES, RulesError, parse_rules
from cryptoinv.scanner import scan_path

RULES = load_rules()
GO_SAMPLES = Path(__file__).parent / "samples_go"


def found(go: str) -> list[tuple[int, str]]:
    return [(f.line, f.algorithm.id) for f in scan_go_source(go, "x.go", RULES)]


def ids(go: str) -> list[str]:
    return [alg for _, alg in found(go)]


# -- imports and package names

def test_single_line_import():
    assert found('import "crypto/md5"\nvar x = md5.Sum(nil)\n') == [(1, "MD5"), (2, "MD5")]


def test_alias_resolves_to_the_right_package():
    go = 'import (\n\th "crypto/sha1"\n)\nfunc f() { h.Sum(nil) }\n'
    assert found(go) == [(2, "SHA1"), (4, "SHA1")]


def test_two_rand_packages_are_not_confused():
    go = ('import (\n\t"crypto/rand"\n\tmr "math/rand"\n)\n'
          "func newToken() { rand.Read(b); mr.Intn(9) }\n")
    assert found(go) == [(2, "CSPRNG"), (5, "CSPRNG"), (5, "INSECURE_RANDOM")]


def test_math_rand_named_rand_outside_secret_context():
    assert ids('import "math/rand"\nfunc shuffle() { rand.Shuffle(n, swap) }\n') == []


def test_versioned_path_uses_the_previous_element():
    assert ids('import "math/rand/v2"\nfunc otp() int { return rand.IntN(999999) }\n') == ["INSECURE_RANDOM"]


def test_subpackage_falls_back_to_parent_path():
    go = 'import "github.com/cloudflare/circl/kem/mlkem/mlkem1024"\nvar s = mlkem1024.Scheme()\n'
    assert ids(go) == ["MLKEM", "MLKEM"]


def test_blank_import_is_reported_once():
    assert found('import _ "crypto/sha1"\n') == [(1, "SHA1")]


def test_unimported_lookalike_is_ignored():
    assert ids("func f() { md5.Sum(nil); rsa.GenerateKey(nil, 512) }\n") == []


def test_raw_strings_and_comments_are_ignored():
    assert ids('import "crypto/md5" // expect\nvar doc = `md5.Sum(x)`\n/* md5.New() */\n') == ["MD5"]


# -- details

def test_key_size_from_short_variable_declaration():
    go = 'import "crypto/rsa"\nfunc f() { bits := 1024\n rsa.GenerateKey(r, bits) }\n'
    [weak] = [f for f in scan_go_source(go, "x.go", RULES) if f.algorithm.id == "RSA_WEAK"]
    assert weak.detail == "key_size=1,024" and weak.line == 3


def test_hash_inside_hmac_is_not_reported_on_its_own():
    go = 'import (\n"crypto/hmac"\n"crypto/md5"\n)\nfunc f() { hmac.New(md5.New, k) }\n'
    assert [x for x in found(go) if x[0] == 5] == [(5, "HMAC_MD5")]


def test_generic_function_declaration_gives_secret_context():
    go = 'import "math/rand"\nfunc makeKey[T any]() int { return rand.Int() }\n'
    assert ids(go) == ["INSECURE_RANDOM"]


@pytest.mark.parametrize("suite, expected", [
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", ["CBC", "RSA", "TDES"]),
    ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", ["CHACHA20_POLY1305"]),
    ("TLS_AES_128_GCM_SHA256", ["AES_GCM"]),
])
def test_tls_cipher_suite_names(suite, expected):
    go = f'import "crypto/tls"\nvar s = tls.{suite}\n'
    assert sorted(ids(go)) == sorted(expected)


def test_dsa_parameter_sizes():
    assert ids('import "crypto/dsa"\nvar p = dsa.L1024N160\n') == ["DSA", "DSA_WEAK"]


# -- folders, report, CBOM, rules

def test_mixed_folder_skips_vendor(tmp_path, capsys):
    (tmp_path / "main.go").write_text('package main\nimport "crypto/des"\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.go").write_text('package lib\nimport "crypto/md5"\n')
    (tmp_path / "tool.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    result = scan_path(tmp_path)
    assert result.languages == {"Go": 1, "Python": 1}
    assert {(f.path, f.algorithm.id) for f in result.findings} == {("main.go", "DES"), ("tool.py", "SHA1")}
    main(["scan", str(tmp_path), "--no-color"])
    assert "2 file(s) scanned (1 Go, 1 Python)" in capsys.readouterr().out


def test_go_findings_make_a_valid_cbom():
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    cbom = build_cbom(scan_path(GO_SAMPLES))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(cbom)) is None
    refs = {c["bom-ref"] for c in cbom["components"]}
    assert {"crypto:MLKEM", "crypto:X25519", "crypto:RSA_WEAK", "crypto:TLS_NO_VERIFY"} <= refs


@pytest.mark.parametrize("break_it, message", [
    (lambda g: g["packages"].update({"crypto/x": "NOPE"}), "unknown algorithm 'NOPE'"),
    (lambda g: g["symbols"].update({"crypto/x.Y": ["MD5", "NOPE"]}), "unknown algorithm 'NOPE'"),
    (lambda g: g["calls"].update({"crypto/x.F": {"algorithm": "MD5", "bits": 1}}), "unknown field"),
    (lambda g: g["secret_context"].append("crypto/nope"), "not in go packages"),
    (lambda g: g["patterns"].append({"regex": "(", "algorithm": "MD5"}), "bad or missing regex"),
])
def test_mistakes_in_go_rules_are_caught(break_it, message):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    break_it(data["go"])
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_rules_without_go_section_skip_go():
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    del data["go"]
    assert scan_path(GO_SAMPLES, parse_rules(data)).findings == []
