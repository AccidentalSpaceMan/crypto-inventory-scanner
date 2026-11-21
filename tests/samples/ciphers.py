"""Sample: symmetric ciphers and modes. Never imported or run; the scanner only reads it."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # expect: AES_GCM, CHACHA20_POLY1305
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4, TripleDES  # expect: RC4, TDES
from Crypto.Cipher import DES  # expect: DES


def ecb(key, data):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # expect: AES, ECB
    return enc.update(data)


def cbc(key, iv, data):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)  # expect: AES, CBC


def gcm(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)  # expect: AES_GCM


def chacha(key, nonce, data):
    return ChaCha20Poly1305(key).encrypt(nonce, data, None)  # expect: CHACHA20_POLY1305


def stream(key, data):
    return Cipher(ARC4(key), mode=None).encryptor().update(data)  # expect: RC4


def triple(key, iv, data):
    return Cipher(TripleDES(key), modes.CTR(iv)).encryptor().update(data)  # expect: TDES, UNAUTH_MODE


def des(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)  # expect: DES, ECB
