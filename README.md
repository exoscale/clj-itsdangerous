# itsdangerous: HMAC'd payloads for web sessions

A Clojure library designed to sign and verity tokens using the
[itsdangerous](https://palletsprojects.com/p/itsdangerous/) scheme.


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

To sign a payload, use the `exoscale.itsdangerous/sign` function:

``` clojure
(sign {:exoscale.itsdangerous/algorithm   :exoscale.itsdangerous/hmac-sha256
       :exoscale.itsdangerous/private-key "A-SECRET-KEY"
       :exoscale.itsdangerous/salt        "session"
       :exoscale.itsdangerous/payload     "{\"user-id\": 1234}"})
;; => "some-token"

(verify {:exoscale.itsdangerous/algorithm   :exoscale.itsdangerous/hmac-sha256
         :exoscale.itsdangerous/private-key "A-SECRET-KEY"
         :exoscale.itsdangerous/salt        "session"
         :exoscale.itsdangerous/token       some-token})
;; => "{\"user-id\": 1234}"
```

## Token validity

By default, a produced token contains a timestamp. This timestamp is the UNIX
epoch in seconds and can be overriden by adding a value
to the `:exoscale.itsdangerous/timestamp` key in the input map to `sign`.

When verifying, an optional `exoscale.itsdangerous/max-age` key can be
added to the map. When a token's signature is valid, but has been signed
more than the value given to `max-age` the verifying process will fail.

`exoscale.itsdangerous/verify` always yield the payload or throws exceptions.
