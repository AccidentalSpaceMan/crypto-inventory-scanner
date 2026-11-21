"""Sample: MACs, key derivation and password hashing. Never imported or run."""
import hashlib
import hmac

import bcrypt  # expect: BCRYPT
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # expect: HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # expect: SCRYPT


def mac_sha1(key, msg):
    return hmac.new(key, msg, hashlib.sha1).digest()  # expect: HMAC_SHA1


def mac_sha256(key, msg):
    return hmac.new(key, msg, "sha256").digest()  # expect: HMAC


def mac_crypto(key):
    return crypto_hmac.HMAC(key, hashes.SHA384())  # expect: HMAC


def weak_pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1000)  # expect: PBKDF2


def strong_pbkdf2(salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)  # expect: PBKDF2_STRONG


def derive(secret):
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"demo").derive(secret)  # expect: HKDF


def slow_hash(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)  # expect: SCRYPT


def bcrypt_hash(password):
    return bcrypt.hashpw(password, bcrypt.gensalt())  # expect: BCRYPT
