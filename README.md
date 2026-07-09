# itsdangerous: HMAC'd payloads for web sessions

A Clojure library designed to sign and verify tokens using the
[itsdangerous](https://palletsprojects.com/projects/itsdangerous/) scheme.


![](https://github.com/exoscale/clj-itsdangerous/workflows/Clojure%20CI/badge.svg)
[![Clojars Project](https://img.shields.io/clojars/v/exoscale/itsdangerous.svg)](https://clojars.org/exoscale/itsdangerous)
[![cljdoc badge](https://cljdoc.org/badge/exoscale/itsdangerous)](https://cljdoc.org/d/exoscale/itsdangerous/CURRENT)

## Key concepts

ItsDangerous relies on the following shared knowledge:

- A private key
- A misnamed *salt*, which isn't the usual salt found in cryptographic systems.
  In ItsDangerous it is used to namespace signed tokens. Precisions at
  https://itsdangerous.palletsprojects.com/en/1.1.x/serializer/#the-salt
- An algorithm

These must be decided out of band between signing and verifying parties.

## Usage

The library exposes two functions: `sign` and `verify`.

### Basic example

``` clojure
(require '[exoscale.itsdangerous :as danger])

(danger/sign {:exoscale.itsdangerous/algorithm    :exoscale.itsdangerous/hmac-sha256
              :exoscale.itsdangerous/private-key  "A-SECRET-KEY"
              :exoscale.itsdangerous/salt         "session"
              :exoscale.itsdangerous/payload      "{\"user-id\": 1234}"})
;; => "some-token"

(danger/verify {:exoscale.itsdangerous/algorithm    :exoscale.itsdangerous/hmac-sha256
                :exoscale.itsdangerous/private-keys ["A-SECRET-KEY"]
                :exoscale.itsdangerous/salt         "session"
                :exoscale.itsdangerous/token         "some-token"})
;; => "{\"user-id\": 1234}"
```

### Configuration parameters

- `:exoscale.itsdangerous/algorithm` — `:exoscale.itsdangerous/hmac-sha1` (default) or `:exoscale.itsdangerous/hmac-sha256`
- `:exoscale.itsdangerous/private-key` — a secret string used to sign tokens (required for `sign`)
- `:exoscale.itsdangerous/private-keys` — a collection of secret strings. All keys are tried when verifying, allowing seamless key rotation (required for `verify`).
- `:exoscale.itsdangerous/salt` — a non-empty string to namespace tokens
- `:exoscale.itsdangerous/signer-type` — controls the token format:
  - `:exoscale.itsdangerous/signer` — raw payload, no timestamp
  - `:exoscale.itsdangerous/timestamp-signer` — raw payload, with timestamp (default)
  - `:exoscale.itsdangerous/url-safe-serializer` — JSON payload, optional zlib compression, no timestamp
  - `:exoscale.itsdangerous/url-safe-timed-serializer` — JSON payload, optional zlib compression, with timestamp
- `:exoscale.itsdangerous/key-derivation` — `:exoscale.itsdangerous/django-concat` (default), `:exoscale.itsdangerous/hmac`, or `:exoscale.itsdangerous/concat`

### Key rotation

Provide multiple keys in `:exoscale.itsdangerous/private-keys`. The first key
signs new tokens. Verification tries all keys, so old tokens signed with a
previous key remain valid:

``` clojure
(danger/verify {:exoscale.itsdangerous/algorithm    :exoscale.itsdangerous/hmac-sha256
                :exoscale.itsdangerous/private-keys ["NEW-KEY" "OLD-KEY"]
                :exoscale.itsdangerous/salt         "session"
                :exoscale.itsdangerous/token         token})
```

### Token validity

By default, tokens include a timestamp (the UNIX epoch in seconds). Override it
with `:exoscale.itsdangerous/timestamp` when signing.

When verifying, pass `:exoscale.itsdangerous/max-age` (in seconds) to reject
tokens older than the given age:

``` clojure
(danger/verify {:exoscale.itsdangerous/algorithm    :exoscale.itsdangerous/hmac-sha256
                :exoscale.itsdangerous/private-keys ["A-SECRET-KEY"]
                :exoscale.itsdangerous/salt         "session"
                :exoscale.itsdangerous/token         token
                :exoscale.itsdangerous/max-age       3600})
;; throws if token is older than 1 hour
```

`verify` yields the payload on success or throws an exception on failure.

## Upstream itsdangerous compatibility

Compatibility is tested against itsdangerous 2.2.0. All signer types, algorithms,
and key derivation methods produce interchangeable tokens.
