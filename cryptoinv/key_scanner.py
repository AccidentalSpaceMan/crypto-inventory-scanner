"""Find and grade certificates and key files (.pem, .crt, .cer, .der, .key, .pub, .csr).

The code scanners find crypto that code *uses*. This one reads crypto *material* lying in the
repository: X.509 certificates (key type and size, signature hash, subject, expiry), public and
private keys, certificate signing requests, SSH keys and Diffie-Hellman parameters.

Parsing certificates means decoding ASN.1, a binary format where hand-written parsers are a
classic source of security bugs, so this uses the well-tested `cryptography` library. It is
optional: without it, these files are listed as skipped with an install hint.

Safety rules:
- Key material is never printed. Findings show only facts about a key: type, size, subject.
- Passwords are never asked for. An encrypted private key is noted, not opened.
- An *unencrypted* private key in the repository is itself a finding, graded BROKEN.
"""
from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .rules import Rules
from .scanner import Finding

PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 .]+)-----.*?-----END \1-----", re.S)
SSH_PUBLIC_KEY = re.compile(
    rb"(?m)^[ \t]*((?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d+"
    rb"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+[A-Za-z0-9+/=]+)")
MISSING_LIBRARY = ("skipped: install the 'cryptography' package (pip install cryptography) to read "
                   "certificate and key files")


@dataclass(frozen=True)
class CertificateInfo:
    """One X.509 certificate found in the repository."""
    path: str
    line: int
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str | None        # algorithm id of the certificate's public key
    signature_algorithm: str | None  # algorithm id of its signature hash (or key, for Ed25519/ML-DSA)
    expired: bool


@dataclass
class KeyFileScan:
    findings: list[Finding] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)     # e.g. encrypted keys we didn't open
    error: str | None = None                           # set when nothing could be read


class _KeyScan:
    def __init__(self, rules: Rules, path: str, data: bytes, now: datetime):
        self.rules, self.keys, self.path, self.data, self.now = rules, rules.keys, path, data, now
        self.out = KeyFileScan()
        self._seen: set[tuple[int, str]] = set()

    # -- helpers

    def line_of(self, offset: int) -> int:
        return self.data.count(b"\n", 0, offset) + 1

    def report(self, line: int, alg_id: str, symbol: str, detail: str, code: str) -> None:
        if (line, alg_id) in self._seen:
            return
        self._seen.add((line, alg_id))
        self.out.findings.append(Finding(self.path, line, self.rules.algorithms[alg_id], symbol, detail, code))

    @staticmethod
    def key_type(public_key) -> tuple[str | None, int | None, str]:
        """(type name, size in bits or None, extra detail) for a public key object."""
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", public_key.key_size, ""
        # DSA and finite-field DH are deprecated in cryptography and may disappear from it one day.
        for module_name, class_name, type_name in (("dsa", "DSAPublicKey", "DSA"), ("dh", "DHPublicKey", "DH")):
            try:
                module = __import__(f"cryptography.hazmat.primitives.asymmetric.{module_name}",
                                    fromlist=[class_name])
            except ImportError:
                continue
            if isinstance(public_key, getattr(module, class_name)):
                return type_name, public_key.key_size, ""
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "EC", None, f"curve {public_key.curve.name}"
        for cls, name in ((ed25519.Ed25519PublicKey, "ED25519"), (ed448.Ed448PublicKey, "ED448"),
                          (x25519.X25519PublicKey, "X25519"), (x448.X448PublicKey, "X448")):
            if isinstance(public_key, cls):
                return name, None, ""
        # Post-quantum key classes are newer; recognise them by name so older library versions work.
        cls_name = type(public_key).__name__.upper().replace("_", "")
        for prefix, name in (("MLDSA", "ML-DSA"), ("MLKEM", "ML-KEM"), ("SLHDSA", "SLH-DSA")):
            if cls_name.startswith(prefix):
                return name, None, ""
        return None, None, ""

    def graded(self, type_name: str | None, bits: int | None) -> tuple[str | None, str]:
        alg_id = self.keys.types.get((type_name or "").upper())
        if alg_id is None:
            return None, ""
        if bits is None:
            return alg_id, ""
        rule = self.keys.key_size.get(alg_id)
        if rule and bits < rule[0]:
            alg_id = rule[1]
        return alg_id, f"key_size={bits:,}"

    def key_finding(self, public_key, line: int, symbol: str, code: str, extra: str = "") -> str | None:
        type_name, bits, type_detail = self.key_type(public_key)
        alg_id, size_detail = self.graded(type_name, bits)
        if alg_id:
            detail = "; ".join(filter(None, [size_detail, type_detail, extra]))
            self.report(line, alg_id, symbol, detail, code)
        return alg_id

    # -- each kind of material

    def certificate(self, cert, line: int, code: str) -> None:
        from cryptography.exceptions import UnsupportedAlgorithm
        subject = cert.subject.rfc4514_string() or "(no subject)"
        issuer = cert.issuer.rfc4514_string() or "(no issuer)"
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
        expired = not_after < self.now
        validity = (f"EXPIRED {not_after:%Y-%m-%d}" if expired else f"valid until {not_after:%Y-%m-%d}")
        symbol = f"certificate {subject}"
        key_alg = self.key_finding(cert.public_key(), line, symbol, code, validity)
        try:
            digest = cert.signature_hash_algorithm
        except UnsupportedAlgorithm:
            digest = None
        signature_alg = self.rules.hash_by_name(digest.name) if digest else None
        if signature_alg:
            hash_name = self.rules.algorithms[signature_alg].name
            self.report(line, signature_alg, f"{symbol} (signature)", f"signed with {hash_name}; {validity}", code)
        self.out.certificates.append(CertificateInfo(
            self.path, line, subject, issuer, not_before, not_after, key_alg,
            signature_alg or key_alg, expired))

    def private_key(self, key, line: int, label: str, code: str) -> None:
        self.key_finding(key.public_key(), line, label.lower(), code)
        self.report(line, "PLAINTEXT_PRIVATE_KEY", label.lower(), "not password-protected", code)

    def pem_block(self, label: str, block: bytes, line: int) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        code = f"-----BEGIN {label}-----"
        if label in ("CERTIFICATE", "X509 CERTIFICATE"):
            self.certificate(x509.load_pem_x509_certificate(block), line, code)
        elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
            csr = x509.load_pem_x509_csr(block)
            subject = csr.subject.rfc4514_string() or "(no subject)"
            self.key_finding(csr.public_key(), line, f"certificate request {subject}", code)
            digest = csr.signature_hash_algorithm
            hash_id = self.rules.hash_by_name(digest.name) if digest else None
            if hash_id:
                self.report(line, hash_id, f"certificate request {subject} (signature)",
                            f"signed with {self.rules.algorithms[hash_id].name}", code)
        elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            self.key_finding(serialization.load_pem_public_key(block), line, "public key", code)
        elif label == "ENCRYPTED PRIVATE KEY" or b"Proc-Type: 4,ENCRYPTED" in block:
            self.out.notes.append(f"line {line}: password-protected private key (not opened, so its "
                                  "algorithm isn't known)")
        elif label == "OPENSSH PRIVATE KEY":
            self.private_key(serialization.load_ssh_private_key(block, password=None), line, label, code)
        elif label.endswith("PRIVATE KEY"):
            self.private_key(serialization.load_pem_private_key(block, password=None), line, label, code)
        elif label in ("DH PARAMETERS", "X9.42 DH PARAMETERS"):
            params = serialization.load_pem_parameters(block)
            alg_id, detail = self.graded("DH", params.parameter_numbers().p.bit_length())
            if alg_id:
                self.report(line, alg_id, "DH parameters", detail, code)

    def der(self) -> bool:
        """Try the binary (DER) forms. Returns True if something was recognised."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        loaders = [
            lambda: self.certificate(x509.load_der_x509_certificate(self.data), 1, "(binary DER certificate)"),
            lambda: self.key_finding(x509.load_der_x509_csr(self.data).public_key(), 1,
                                     "certificate request", "(binary DER certificate request)"),
            lambda: self.key_finding(serialization.load_der_public_key(self.data), 1,
                                     "public key", "(binary DER public key)"),
            lambda: self.private_key(serialization.load_der_private_key(self.data, password=None), 1,
                                     "PRIVATE KEY", "(binary DER private key)"),
        ]
        for load in loaders:
            try:
                load()
                return True
            except TypeError:   # an encrypted private key
                self.out.notes.append("password-protected private key (not opened)")
                return True
            except Exception:   # not this kind of file: try the next loader
                continue
        return False

    def scan(self) -> KeyFileScan:
        from cryptography.exceptions import UnsupportedAlgorithm
        recognised = False
        for m in PEM_BLOCK.finditer(self.data):
            label, line = m.group(1).decode("ascii"), self.line_of(m.start())
            recognised = True
            try:
                self.pem_block(label, m.group(0), line)
            except TypeError:   # password-protected (e.g. an encrypted OpenSSH key)
                self.out.notes.append(f"line {line}: password-protected private key (not opened)")
            except (ValueError, UnsupportedAlgorithm) as e:
                self.out.notes.append(f"line {line}: couldn't read {label.lower()}: {e}")
        for m in SSH_PUBLIC_KEY.finditer(self.data):
            from cryptography.hazmat.primitives import serialization
            recognised = True
            kind = m.group(1).split()[0].decode("ascii")
            line = self.line_of(m.start(1))
            try:
                key = serialization.load_ssh_public_key(m.group(1))
            except (ValueError, UnsupportedAlgorithm) as e:
                self.out.notes.append(f"line {line}: couldn't read SSH key: {e}")
                continue
            self.key_finding(key, line, f"SSH public key ({kind})", f"{kind} ... (SSH public key)")
        if not recognised and not self.der():
            self.out.error = "no certificate or key found in this file"
        return self.out


def scan_key_file(data: bytes, path: str, rules: Rules, now: datetime | None = None) -> KeyFileScan:
    """Read one certificate or key file."""
    if rules.keys is None:
        return KeyFileScan()
    try:
        import cryptography  # noqa: F401
        from cryptography.utils import CryptographyDeprecationWarning
    except ImportError:
        return KeyFileScan(error=MISSING_LIBRARY)
    # Reading DSA or DH material makes cryptography warn that it is deprecated. We read it on
    # purpose, to flag it, so keep those warnings out of the report.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return _KeyScan(rules, path, data, now or datetime.now(timezone.utc)).scan()
