"""Sample: insecure and secure randomness. Never imported or run."""
import os
import random
import secrets  # expect: CSPRNG
from random import choice


def shuffle_deck(cards):
    random.shuffle(cards)  # a game, not a secret: no finding
    return cards


def make_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))  # expect: INSECURE_RANDOM


def reset_code():
    otp = random.randint(100000, 999999)  # expect: INSECURE_RANDOM
    return otp


def session_id():
    return "".join(choice("abc123") for _ in range(16))  # expect: INSECURE_RANDOM


def settings():
    return {"api_key": random.getrandbits(128)}  # expect: INSECURE_RANDOM


def good_token():
    return secrets.token_hex(16)  # expect: CSPRNG


def good_key():
    return os.urandom(32)  # expect: CSPRNG


def dice():
    return random.SystemRandom().randint(1, 6)  # expect: CSPRNG
