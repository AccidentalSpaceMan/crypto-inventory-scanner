"""Sample: public-key crypto, classical and post-quantum. Never imported or run."""
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa  # expect: DSA, ECC, RSA
from cryptography.hazmat.primitives.asymmetric import dh  # expect: DH
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # expect: ED25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # expect: X25519
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey  # expect: MLKEM
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # expect: MLDSA


def weak_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)  # expect: RSA_WEAK


def ok_rsa():
    return rsa.generate_private_key(65537, 3072)  # expect: RSA


def unknown_size(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # expect: RSA


def weak_dsa():
    return dsa.generate_private_key(key_size=1024)  # expect: DSA_WEAK


def weak_dh():
    return dh.generate_parameters(generator=2, key_size=2**10)  # expect: DH_WEAK


def ecdsa():
    return ec.generate_private_key(ec.SECP256R1())  # expect: ECC


def ecdh(key, peer):
    return key.exchange(ec.ECDH(), peer)  # expect: ECDH


def hybrid_keys():
    return X25519PrivateKey.generate(), MLKEM768PrivateKey.generate()  # expect: X25519, MLKEM


def hybrid_signing():
    return Ed25519PrivateKey.generate(), MLDSA65PrivateKey.generate()  # expect: ED25519, MLDSA
