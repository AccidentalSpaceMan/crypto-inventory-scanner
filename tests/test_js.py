"""JavaScript / TypeScript scanning beyond the sample files."""
import json
from pathlib import Path

import pytest

from cryptoinv import load_rules
from cryptoinv.cbom import build_cbom
from cryptoinv.cli import main
from cryptoinv.js_scanner import scan_js_source
from cryptoinv.rules import DEFAULT_RULES, RulesError, parse_rules
from cryptoinv.scanner import scan_path
from cryptoinv.textscan import mask

RULES = load_rules()
JS_SAMPLES = Path(__file__).parent / "samples_js"


def ids(js: str) -> list[str]:
    return [f.algorithm.id for f in scan_js_source(js, "x.js", RULES)]


# -- masking

def test_division_is_not_a_regex():
    assert ids("const r = a / 2; crypto.createHash('md5'); const q = b / 4;") == ["MD5"]


def test_regex_literal_with_quotes_is_masked():
    _, masked = mask("const re = /'md5'/g; x = 1;", js=True)
    assert "md5" not in masked and "x = 1" in masked


def test_regex_after_return_keyword():
    assert ids("function f(s) { return /\"/.test(s) }\ncrypto.createHash('sha1');") == ["SHA1"]


def test_template_strings_are_strings():
    assert ids("const doc = `call crypto.createHash('md5') ${x}`;") == []


def test_template_string_as_argument():
    assert ids("crypto.createHash(`sha512`);") == ["SHA512"]


# -- imports

@pytest.mark.parametrize("header, call", [
    ("const c = require('crypto');", "c.createHash('md5')"),
    ("import * as nc from 'node:crypto';", "nc.createHash('md5')"),
    ("import nodeCrypto from 'crypto';", "nodeCrypto.createHash('md5')"),
    ("import { createHash as ch } from 'crypto';", "ch('md5')"),
    ("const {\n  createHash: digest,\n} = require('crypto');", "digest('md5')"),
    ("import nc = require('crypto');", "nc.createHash('md5')"),            # TypeScript
    ("", "crypto.createHash('md5')"),                                       # global / conventional name
])
def test_import_styles(header, call):
    assert ids(f"{header}\n{call};\n") == ["MD5"]


def test_same_function_name_from_another_module_is_ignored():
    assert ids("import { createHash } from './my-hash';\ncreateHash('md5');\n") == []


def test_other_objects_with_crypto_method_names_are_ignored():
    assert ids("const lib = require('./lib');\nlib.createHash('md5');\n") == []


# -- names and details

@pytest.mark.parametrize("name, expected", [
    ("aes-256-cbc", ["AES", "CBC"]),
    ("AES-128-CTR", ["AES", "UNAUTH_MODE"]),
    ("aes-192-ccm", ["AES_AEAD_OTHER"]),
    ("id-aes256-gcm", ["AES_GCM"]),
    ("des-ede3-cbc", ["CBC", "TDES"]),
    ("des-cbc", ["CBC", "DES"]),
    ("bf-cbc", ["CBC", "OLD_BLOCK"]),
    ("rc4", ["RC4"]),
    ("rc4-40", ["RC4"]),
    ("chacha20-poly1305", ["CHACHA20_POLY1305"]),
    ("chacha20", ["CHACHA20"]),
    ("not-a-cipher", []),
])
def test_openssl_cipher_names(name, expected):
    assert sorted(ids(f"crypto.createCipheriv('{name}', k, iv);")) == sorted(expected)


def test_dh_sizes():
    assert ids("crypto.createDiffieHellman(512);") == ["DH_WEAK"]
    assert ids("crypto.createDiffieHellman(4096);") == ["DH"]
    assert ids("crypto.getDiffieHellman('modp14');") == ["DH"]


def test_password_hash_needs_update_with_password_name():
    assert ids("crypto.createHash('sha256').update(userPassword);") == ["UNSALTED_PASSWORD_HASH"]
    assert ids("crypto.createHash('sha256').update(fileContents);") == ["SHA256"]


def test_jwt_without_algorithm_option_is_not_guessed():
    assert ids("jwt.sign(payload, secret);") == []


def test_webcrypto_nested_hash_belongs_to_its_algorithm():
    found = scan_js_source("subtle.importKey('raw', k, { name: 'HMAC', hash: { name: 'SHA-1' } }, false, []);",
                           "x.js", RULES)
    assert [(f.algorithm.id, f.detail) for f in found] == [("HMAC_SHA1", "hash: SHA-1")]


def test_secret_context_from_arrow_function_name():
    assert ids("const makeSessionId = () => Math.random().toString(36);") == ["INSECURE_RANDOM"]
    assert ids("const jitter = () => Math.random() * 100;") == []


def test_constant_with_typescript_annotation():
    assert ids("const ALG: string = 'md5';\ncrypto.createHash(ALG);\n") == ["MD5"]


def test_symbol_and_detail():
    [f] = [f for f in scan_path(JS_SAMPLES / "node_crypto.js").findings if f.algorithm.id == "RSA_WEAK"]
    assert f.symbol == "crypto.generateKeyPairSync('rsa')" and f.detail == "key_size=1,024"


# -- folders, CBOM, rules

def test_folder_skips_minified_and_declaration_files(tmp_path, capsys):
    (tmp_path / "app.ts").write_text("crypto.createHash('md5');\n")
    (tmp_path / "vendor.min.js").write_text("crypto.createHash('sha1');\n")
    (tmp_path / "types.d.ts").write_text("export declare function createHash(a: string): Hash;\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("crypto.createHash('sha1');\n")
    result = scan_path(tmp_path)
    assert result.languages == {"TypeScript": 1}
    assert [(f.path, f.algorithm.id) for f in result.findings] == [("app.ts", "MD5")]
    main(["scan", str(tmp_path), "--no-color"])
    assert "1 file(s) scanned (1 TypeScript)" in capsys.readouterr().out


def test_js_findings_make_a_valid_cbom():
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    cbom = build_cbom(scan_path(JS_SAMPLES))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(cbom)) is None
    jwt_none = next(c for c in cbom["components"] if c["bom-ref"] == "crypto:JWT_NONE")
    assert {o["location"] for o in jwt_none["evidence"]["occurrences"]} == {"tokens.ts"}


@pytest.mark.parametrize("break_it, message", [
    (lambda j: j["node_names"].update(foo="NOPE"), "unknown algorithm 'NOPE'"),
    (lambda j: j["webcrypto"].update({"X": ["AES", "NOPE"]}), "unknown algorithm 'NOPE'"),
    (lambda j: j["cipher_default_modes"].update({"des": "xyz"}), "unknown mode 'xyz'"),
    (lambda j: j["patterns"].append({"regex": "[", "algorithm": "MD5"}), "bad or missing regex"),
    (lambda j: j.update(extra=1), "unknown field"),
])
def test_mistakes_in_javascript_rules_are_caught(break_it, message):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    break_it(data["javascript"])
    with pytest.raises(RulesError, match=message):
        parse_rules(data)


def test_rules_without_javascript_section_skip_js():
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    del data["javascript"]
    assert scan_path(JS_SAMPLES, parse_rules(data)).findings == []
