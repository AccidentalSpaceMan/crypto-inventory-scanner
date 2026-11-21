"""Sample: weak and strong hashes. Never imported or run; the scanner only reads it.

An "expect" comment at the end of a line lists the algorithm ids the scanner must find
there. Lines without one must produce no findings.
"""
import hashlib
from hashlib import md5  # expect: MD5

from cryptography.hazmat.primitives import hashes


def checksum(data):
    return hashlib.md5(data).hexdigest()  # expect: MD5


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()  # expect: SHA1


def old_style(data):
    return md5(data).digest()  # expect: MD5


def by_name(data):
    return hashlib.new("sha1", data).hexdigest()  # expect: SHA1


def not_for_security(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # expect: MD5


def good(data):
    return hashlib.sha256(data).hexdigest()  # expect: SHA256


def also_good(data):
    digest = hashes.Hash(hashes.SHA3_256())  # expect: SHA3
    digest.update(data)
    return digest.finalize()


def store_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # expect: UNSALTED_PASSWORD_HASH


def mention_in_comment():
    # hashlib.md5 in a comment or "hashlib.md5" in a string is not a finding
    return "hashlib.md5"
