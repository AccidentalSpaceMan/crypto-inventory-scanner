"""Certificates and key files. All key material is generated here, never committed."""
import json
import sys

import pytest
from conftest import (make_cert, make_sha1_rsa_cert, openssh_private, openssh_public,
                      private_pem, public_pem)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed25519, rsa, x25519

from cryptoinv import load_rules
from cryptoinv.cbom import build_cbom
from cryptoinv.cli import main
from cryptoinv.key_scanner import MISSING_LIBRARY, scan_key_file
from cryptoinv.rules import DEFAULT_RULES, RulesError, parse_rules
from cryptoinv.scanner import scan_path

RULES = load_rules()


@pytest.fixture(scope="module")
def rsa1024():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def rsa2048():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def scan(data: bytes, name: str = "x.pem"):
    return scan_key_file(data, name, RULES)


def found(data: bytes) -> set[tuple[int, str]]:
    return {(f.line, f.algorithm.id) for f in scan(data).findings}


# -- certificates

def test_weak_old_certificate(rsa1024):
    result = scan(make_sha1_rsa_cert(rsa1024, "legacy.example", expired=True))
    assert {(f.line, f.algorithm.id) for f in result.findings} == {(1, "RSA_WEAK"), (1, "SHA1")}
    [cert] = result.certificates
    assert cert.subject == "CN=legacy.example" and cert.expired
    assert (cert.key_algorithm, cert.signature_algorithm) == ("RSA_WEAK", "SHA1")
    weak = next(f for f in result.findings if f.algorithm.id == "RSA_WEAK")
    assert weak.detail.startswith("key_size=1,024; EXPIRED ")
    assert weak.code == "-----BEGIN CERTIFICATE-----"   # never the key material itself


def test_modern_ec_certificate():
    key = ec.generate_private_key(ec.SECP384R1())
    result = scan(make_cert(key, "api.example", hashes.SHA384()))
    assert {f.algorithm.id for f in result.findings} == {"ECC", "SHA384"}
    ecc = next(f for f in result.findings if f.algorithm.id == "ECC")
    assert "curve secp384r1" in ecc.detail and "valid until" in ecc.detail
    assert not result.certificates[0].expired


def test_ed25519_certificate_signature_is_the_key_itself():
    result = scan(make_cert(ed25519.Ed25519PrivateKey.generate(), "edge.example"))
    assert [f.algorithm.id for f in result.findings] == ["ED25519"]
    assert result.certificates[0].signature_algorithm == "ED25519"


def test_post_quantum_certificate():
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    result = scan(make_cert(mldsa.MLDSA65PrivateKey.generate(), "pq.example"))
    assert [f.algorithm.id for f in result.findings] == ["MLDSA"]


def test_certificate_bundle_reports_each_at_its_line(rsa2048):
    ec_cert = make_cert(ec.generate_private_key(ec.SECP256R1()), "b.example", hashes.SHA256())
    bundle = make_cert(rsa2048, "a.example", hashes.SHA256()) + b"\n" + ec_cert
    result = scan(bundle)
    second_line = bundle[:bundle.index(ec_cert)].count(b"\n") + 1
    assert [c.line for c in result.certificates] == [1, second_line]
    assert found(bundle) == {(1, "RSA"), (1, "SHA256"), (second_line, "ECC"), (second_line, "SHA256")}


def test_binary_der_certificate(rsa2048):
    assert found(make_cert(rsa2048, "der.example", hashes.SHA256(), pem=False)) == {(1, "RSA"), (1, "SHA256")}


def test_certificate_request(rsa1024):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "req.example")]))
           .sign(rsa1024, hashes.SHA256()))
    assert found(csr.public_bytes(serialization.Encoding.PEM)) == {(1, "RSA_WEAK"), (1, "SHA256")}


# -- keys

def test_unencrypted_private_key_is_broken(rsa2048):
    result = scan(private_pem(rsa2048, traditional=True), "server.key")
    assert {f.algorithm.id for f in result.findings} == {"RSA", "PLAINTEXT_PRIVATE_KEY"}
    leak = next(f for f in result.findings if f.algorithm.id == "PLAINTEXT_PRIVATE_KEY")
    assert leak.grade == "BROKEN" and leak.code == "-----BEGIN RSA PRIVATE KEY-----"


def test_encrypted_private_key_is_noted_not_opened(rsa2048):
    result = scan(private_pem(rsa2048, password=b"correct horse"), "protected.key")
    assert result.findings == [] and result.error is None
    assert "password-protected" in result.notes[0]


def test_legacy_encrypted_pem_is_noted(rsa2048):
    data = rsa2048.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.BestAvailableEncryption(b"pw"))
    assert b"Proc-Type: 4,ENCRYPTED" in data
    assert scan(data).findings == [] and "password-protected" in scan(data).notes[0]


def test_openssh_private_key():
    key = ed25519.Ed25519PrivateKey.generate()
    assert {f.algorithm.id for f in scan(openssh_private(key), "id_ed25519").findings} == {
        "ED25519", "PLAINTEXT_PRIVATE_KEY"}


def test_password_protected_openssh_private_key():
    pytest.importorskip("bcrypt")   # cryptography needs it to *create* encrypted OpenSSH keys
    key = ed25519.Ed25519PrivateKey.generate()
    protected = scan(openssh_private(key, password=b"pw"), "id_ed25519")
    assert protected.findings == [] and "password-protected" in protected.notes[0]


def test_public_keys(rsa1024):
    assert found(public_pem(rsa1024)) == {(1, "RSA_WEAK")}
    assert found(public_pem(x25519.X25519PrivateKey.generate())) == {(1, "X25519")}


def test_ssh_public_keys(rsa1024):
    dsa_key = dsa.generate_private_key(key_size=1024)
    data = openssh_public(ed25519.Ed25519PrivateKey.generate()) + openssh_public(rsa1024) + openssh_public(dsa_key)
    result = scan(data, "authorized_keys.pub")
    assert {(f.line, f.algorithm.id) for f in result.findings} == {(1, "ED25519"), (2, "RSA_WEAK"), (3, "DSA_WEAK")}
    assert result.findings[0].code.endswith("(SSH public key)") and "AAAA" not in result.findings[0].code


def test_dh_parameters():
    params = dh.generate_parameters(generator=2, key_size=512)
    pem = params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
    assert found(pem) == {(1, "DH_WEAK")}


# -- unreadable files

def test_file_without_keys_is_an_error_not_a_crash():
    result = scan(b"just some text\n", "notes.pem")
    assert result.findings == [] and result.error == "no certificate or key found in this file"


def test_broken_pem_block_is_a_note():
    result = scan(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")
    assert result.findings == [] and "couldn't read certificate" in result.notes[0]


def test_missing_cryptography_library(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography", None)   # makes "import cryptography" fail
    assert scan_key_file(b"anything", "x.pem", RULES).error == MISSING_LIBRARY


# -- folders, report and CBOM

@pytest.fixture
def repo(tmp_path, rsa1024, rsa2048):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "legacy.CRT").write_bytes(make_sha1_rsa_cert(rsa1024, "legacy.example", expired=True))
    (certs / "server.key").write_bytes(private_pem(rsa2048))
    (certs / "protected.key").write_bytes(private_pem(rsa2048, password=b"pw"))
    (certs / "readme.pem").write_text("no keys here\n")
    return tmp_path


def test_folder_scan_and_report(repo, capsys):
    result = scan_path(repo)
    assert result.languages == {"Key/cert": 3, "Python": 1}       # readme.pem is skipped
    assert [path for path, _ in result.errors] == ["certs/readme.pem"]
    assert [path for path, _ in result.notes] == ["certs/protected.key"]
    main(["scan", str(repo), "--no-color"])
    out = capsys.readouterr().out
    assert "4 file(s) scanned (3 Key/cert, 1 Python)" in out
    assert "Unencrypted private key stored in the code base" in out
    assert "Certificates (1)" in out and "CN=legacy.example" in out and "EXPIRED" in out
    assert "signature: SHA-1" in out
    assert "Notes" in out and "password-protected" in out


def test_certificates_in_a_valid_cbom(repo):
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    cbom = build_cbom(scan_path(repo))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(cbom)) is None
    [cert] = [c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
    props = cert["cryptoProperties"]["certificateProperties"]
    assert props["subjectName"] == "CN=legacy.example"
    assert props["signatureAlgorithmRef"] == "crypto:SHA1" and props["certificateFormat"] == "X.509"
    assert {"name": "cryptoinv:expired", "value": "true"} in cert["properties"]
    deps = {d["ref"]: d["dependsOn"] for d in cbom["dependencies"]}
    assert deps[cert["bom-ref"]] == ["crypto:RSA_WEAK", "crypto:SHA1"]
    assert cert["bom-ref"] in deps["application"]


# -- rules

def test_mistakes_in_key_rules_are_caught():
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    data["keys"]["types"]["RSA"] = "NOPE"
    with pytest.raises(RulesError, match="unknown algorithm 'NOPE'"):
        parse_rules(data)


def test_rules_without_keys_section_skip_key_files(rsa1024):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    del data["keys"]
    assert scan_key_file(public_pem(rsa1024), "k.pem", parse_rules(data)).findings == []
