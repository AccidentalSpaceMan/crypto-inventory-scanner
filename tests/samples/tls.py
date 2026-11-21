"""Sample: TLS settings. Never imported or run (and it would only talk to example.com)."""
import ssl

import requests


def insecure_fetch():
    return requests.get("https://example.com", verify=False)  # expect: TLS_NO_VERIFY


def unverified():
    return ssl._create_unverified_context()  # expect: TLS_NO_VERIFY


def old_protocol():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # expect: TLS_OLD


def turn_off_checks():
    ctx = ssl.create_default_context()  # expect: TLS_MODERN
    ctx.check_hostname = False  # expect: TLS_NO_VERIFY
    ctx.verify_mode = ssl.CERT_NONE  # expect: TLS_NO_VERIFY
    return ctx


def modern():
    ctx = ssl.create_default_context()  # expect: TLS_MODERN
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # expect: TLS_MODERN
    return ctx
