"""Shared test helpers: certificates and keys generated on the fly.

The repository never contains real or test private keys (committing keys, even fake ones, is a bad
habit, and GitHub's secret scanning would rightly flag them). Tests that need key material make it
here, in a temporary folder, and it disappears afterwards.
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

NOW = datetime.datetime.now(datetime.timezone.utc)
_SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b")   # DER-encoded algorithm identifiers
_SHA1_WITH_RSA = bytes.fromhex("06092a864886f70d010105")


def make_cert(key, cn: str, hash_alg=None, days_valid: int = 365, expired: bool = False,
              pem: bool = True) -> bytes:
    """A self-signed certificate for `key`. hash_alg=None is for Ed25519 / ML-DSA keys."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = NOW - datetime.timedelta(days=days_valid + 30 if expired else 1)
    end = NOW - datetime.timedelta(days=30) if expired else NOW + datetime.timedelta(days=days_valid)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end).sign(key, hash_alg))
    return cert.public_bytes(serialization.Encoding.PEM if pem else serialization.Encoding.DER)


def make_sha1_rsa_cert(rsa_key, cn: str, expired: bool = False) -> bytes:
    """A genuinely valid SHA-1-signed certificate.

    Modern cryptography refuses to create these (good!), but old ones still sit in real repos and
    the scanner must recognise them. So: build a SHA-256 certificate, swap the algorithm label for
    SHA-1 (same length, so nothing else moves) and sign it again with SHA-1.
    """
    cert = x509.load_pem_x509_certificate(make_cert(rsa_key, cn, hashes.SHA256(), expired=expired))
    tbs = cert.tbs_certificate_bytes.replace(_SHA256_WITH_RSA, _SHA1_WITH_RSA)
    signature = rsa_key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    der = cert.public_bytes(serialization.Encoding.DER).replace(_SHA256_WITH_RSA, _SHA1_WITH_RSA)
    patched = x509.load_der_x509_certificate(der[:-len(signature)] + signature)
    return patched.public_bytes(serialization.Encoding.PEM)


def private_pem(key, password: bytes | None = None, traditional: bool = False) -> bytes:
    fmt = serialization.PrivateFormat.TraditionalOpenSSL if traditional else serialization.PrivateFormat.PKCS8
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc)


def public_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def openssh_public(key, comment: str = "demo@laptop") -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH) + f" {comment}\n".encode()


def openssh_private(key, password: bytes | None = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc)
