#!/usr/bin/env python3
"""Compatibility bridge between clj-itsdangerous and Python itsdangerous.

Subcommands:
  generate              — emit JSON array of tokens for all signer/alg/derivation combos
  generate-compressed   — same but with a large payload that triggers zlib compression
  verify                — read a JSON object on stdin, verify its token, emit JSON result
"""

import hashlib
import json
import sys
import time as _time
import zlib

FIXED_TIMESTAMP = 1700000000
_time.time = lambda: float(FIXED_TIMESTAMP)

from itsdangerous import (
    Signer,
    TimestampSigner,
    URLSafeSerializer,
    URLSafeTimedSerializer,
)
from itsdangerous.encoding import base64_encode

SECRET = "secret-key"
SALT = "cookie-session"
PAYLOAD = "my-payload"
LARGE_PAYLOAD = "x" * 200

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

URLSAFE_SIGNERS = {"URLSafeSerializer", "URLSafeTimedSerializer"}
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


def _sign(signer, signer_type, payload):
    if signer_type in ("Signer", "TimestampSigner"):
        token = signer.sign(payload)
    else:
        token = signer.dumps(payload)
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
                token = _sign(signer, signer_type, PAYLOAD)
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


def generate_compressed():
    """Generate tokens with a large payload that triggers zlib compression.

    Only URLSafeSerializer and URLSafeTimedSerializer use compression.
    """
    results = []
    for signer_type in sorted(URLSAFE_SIGNERS):
        for alg_name in sorted(ALGORITHMS):
            for kd in KEY_DERIVATIONS:
                signer = create_signer(signer_type, alg_name, kd)
                token = _sign(signer, signer_type, LARGE_PAYLOAD)

                # Verify the payload part is actually compressed (starts with ".")
                payload_part = token.split(".")[0] if "." in token else token
                # For URLSafeTimedSerializer, the first "."-separated part is
                # the payload (which may start with "." if compressed)
                # Actually, the token is: payload.timestamp.signature
                # and payload itself may start with "." if compressed
                # So the token may start with ".." when compressed
                is_compressed = token.startswith("..") or (
                    "." in token
                    and token.split(".", 2)[0] == ""
                    and token.count(".") >= 2
                )
                # Simpler check: the first base64 char is "."
                is_compressed = token.startswith(".")

                results.append(
                    {
                        "signer": signer_type,
                        "algorithm": alg_name,
                        "key_derivation": kd,
                        "token": token,
                        "secret": SECRET,
                        "salt": SALT,
                        "payload": LARGE_PAYLOAD,
                        "timestamp": FIXED_TIMESTAMP
                        if signer_type in TIMED_SIGNERS
                        else None,
                        "compressed": is_compressed,
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
        print("Usage: compat.py <generate|generate-compressed|verify>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "generate":
        print(json.dumps(generate()))
    elif cmd == "generate-compressed":
        print(json.dumps(generate_compressed()))
    elif cmd == "verify":
        print(json.dumps(verify()))
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
