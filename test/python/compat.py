#!/usr/bin/env python3
"""Compatibility bridge between clj-itsdangerous and Python itsdangerous.

Subcommands:
  generate   — emit a JSON array of tokens for every signer/algorithm/derivation
  verify     — read a JSON object on stdin, verify its token, emit JSON result
"""

import hashlib
import json
import sys
import time as _time

FIXED_TIMESTAMP = 1700000000
_time.time = lambda: float(FIXED_TIMESTAMP)

from itsdangerous import (
    Signer,
    TimestampSigner,
    URLSafeSerializer,
    URLSafeTimedSerializer,
)

SECRET = "secret-key"
SALT = "cookie-session"
PAYLOAD = "my-payload"

ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}

KEY_DERIVATIONS = ["hmac", "concat", "django-concat"]

SIGNER_TYPES = [
    "Signer",
    "TimestampSigner",
    "URLSafeSerializer",
    "URLSafeTimedSerializer",
]

TIMED_SIGNERS = {"TimestampSigner", "URLSafeTimedSerializer"}


def create_signer(signer_type, algorithm, key_derivation):
    kwargs = {
        "digest_method": ALGORITHMS[algorithm],
        "key_derivation": key_derivation,
    }
    if signer_type == "Signer":
        return Signer(SECRET, salt=SALT, **kwargs)
    if signer_type == "TimestampSigner":
        return TimestampSigner(SECRET, salt=SALT, **kwargs)
    if signer_type == "URLSafeSerializer":
        return URLSafeSerializer(SECRET, salt=SALT, signer_kwargs=kwargs)
    if signer_type == "URLSafeTimedSerializer":
        return URLSafeTimedSerializer(SECRET, salt=SALT, signer_kwargs=kwargs)
    raise ValueError(f"Unknown signer type: {signer_type}")


def _sign(signer, signer_type):
    if signer_type in ("Signer", "TimestampSigner"):
        token = signer.sign(PAYLOAD)
    else:
        token = signer.dumps(PAYLOAD)
    if isinstance(token, bytes):
        token = token.decode()
    return token


def _unsign(signer, signer_type, token):
    if signer_type in ("Signer", "TimestampSigner"):
        result = signer.unsign(token)
    else:
        result = signer.loads(token)
    if isinstance(result, bytes):
        result = result.decode()
    return result


def generate():
    results = []
    for signer_type in SIGNER_TYPES:
        for alg_name in ALGORITHMS:
            for kd in KEY_DERIVATIONS:
                signer = create_signer(signer_type, alg_name, kd)
                token = _sign(signer, signer_type)
                results.append(
                    {
                        "signer": signer_type,
                        "algorithm": alg_name,
                        "key_derivation": kd,
                        "token": token,
                        "secret": SECRET,
                        "salt": SALT,
                        "payload": PAYLOAD,
                        "timestamp": FIXED_TIMESTAMP
                        if signer_type in TIMED_SIGNERS
                        else None,
                    }
                )
    return results


def verify():
    spec = json.loads(sys.stdin.read())
    signer = create_signer(
        spec["signer"],
        spec["algorithm"],
        spec["key_derivation"],
    )
    try:
        payload = _unsign(signer, spec["signer"], spec["token"])
        return {"valid": True, "payload": payload}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def main():
    if len(sys.argv) < 2:
        print("Usage: compat.py <generate|verify>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "generate":
        print(json.dumps(generate()))
    elif cmd == "verify":
        print(json.dumps(verify()))
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
