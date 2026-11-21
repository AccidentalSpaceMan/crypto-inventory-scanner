"""Sample: renamed imports, and local names that only look like crypto. Never imported or run."""
import hashlib as h
from cryptography.hazmat.primitives.asymmetric import rsa as r  # expect: RSA
from cryptography.hazmat.primitives.ciphers import algorithms as algs
from Cryptodome.Hash import SHA1  # expect: SHA1


def digest(data):
    return h.md5(data).hexdigest()  # expect: MD5


def keypair():
    return r.generate_private_key(public_exponent=65537, key_size=512)  # expect: RSA_WEAK


def cipher(key):
    return algs.TripleDES(key)  # expect: TDES


def pycryptodomex(data):
    return SHA1.new(data).hexdigest()  # expect: SHA1


def unrelated():
    md5 = "just a variable name"
    rsa = md5.upper()
    return rsa
