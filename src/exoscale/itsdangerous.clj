(ns exoscale.itsdangerous
  "ItsDangerous signed token implementation.

   This namespace provides two main signatures: `sign` and `verify`,
   refer to their documentation for details. ItsDangerous uses a simple
   HMAC-based scheme to sign credentials. It is widely used in the Python
   world, especially in Flask applications.

   See https://itsdangerous.palletsprojects.com/ for more details."
  (:require [exoscale.ex                 :as ex]
            [clojure.data.json           :as json]
            [clojure.string              :as str]
            [constance.comp              :as comp]
            [exoscale.itsdangerous.hmac  :as hmac]
            [exoscale.itsdangerous.codec :as codec]
            [exoscale.itsdangerous.zlib  :as zlib]
            [exoscale.itsdangerous.spec  :as spec]))

(defn- epoch
  "UNIX epoch in seconds"
  []
  (quot (System/currentTimeMillis) 1000))

;; --- Token parsing ---

(def ^:private timed-signer-types
  "Signer types that include a timestamp in the token."
  #{::timestamp-signer ::url-safe-timed-serializer})

(defn- parse-token
  "Split a ItsDangerous token into its constituent parts using rsplit-style
   parsing (matching Python's Signer/TimestampSigner unsign logic).

   The `signer-type` determines whether the token has a timestamp part:
   - Timed types (`::timestamp-signer`, `::url-safe-timed-serializer`):
     token = value.timestamp.signature  (3 parts via 2 rsplit-on-dot)
   - Untimed types (`::signer`, `::url-safe-serializer`):
     token = value.signature  (2 parts via 1 rsplit-on-dot)

   Returns a map with:
   - `::payload-part`  — the raw payload part (may start with `.` for compressed)
   - `::timestamp-part` — the base64 timestamp part, or nil for untimed tokens
   - `::timestamp`      — the decoded timestamp integer (0 if not present)
   - `::to-sign`        — the string that was signed (payload part + optional timestamp)
   - `::signature`      — the signature part"
  [s signer-type]
  (try
    (let [timed? (contains? timed-signer-types signer-type)
          url-safe? (contains? #{::url-safe-serializer ::url-safe-timed-serializer} signer-type)
          ;; For URL-safe signers, enforce strict dot count (adjusted for compression marker)
          _ (when url-safe?
              (let [dot-count (count (filter #(= % \.) s))
                    adjusted (if (.startsWith ^String s ".") (dec dot-count) dot-count)]
                (when (not= adjusted (if timed? 2 1))
                  (ex/ex-incorrect! "wrong token format" {::token s}))))
          ;; Split on last dot: everything before is value, after is signature
          last-dot (.lastIndexOf ^String s ".")
          _ (when (neg? last-dot)
              (ex/ex-incorrect! "wrong token format" {::token s}))
          value (subs s 0 last-dot)
          sig   (subs s (inc last-dot))
          ;; For timed types, split value on last dot to extract timestamp
          [payload-part timestamp-part]
          (if timed?
            (let [prev-dot (.lastIndexOf ^String value ".")]
              (if (neg? prev-dot)
                (ex/ex-incorrect! "wrong token format (missing timestamp)" {::token s})
                [(subs value 0 prev-dot) (subs value (inc prev-dot))]))
            [value nil])
          timestamp (if timestamp-part
                      (codec/b64->int timestamp-part)
                      0)
          to-sign   (if timestamp-part
                      (str payload-part "." timestamp-part)
                      payload-part)]
      {::payload-part   payload-part
       ::timestamp-part timestamp-part
       ::timestamp      timestamp
       ::to-sign        to-sign
       ::signature      sig})
    (catch Exception e
      (ex/ex-incorrect! "error while processing token" {::token s} e))))

(defn- signature-for
  "Compute the signature of a to-sign string. Yields the signature in Base64.

   Uses the configured algorithm, salt, and key derivation method."
  [{::keys [algorithm salt key-derivation] :as config} to-sign private-key]
  (let [key-derivation (or key-derivation ::django-concat)
        derived-key    (hmac/derive-key algorithm key-derivation private-key salt)]
    (codec/b->b64 (hmac/hmac-sign algorithm to-sign derived-key))))

(defn- signatures-for
  "Yield all possible signatures for a to-sign string, based on the config.
   Includes fallback algorithm/key-derivation combinations."
  [{::keys [algorithm salt key-derivation private-keys fallbacks] :as config} to-sign]
  (let [key-derivation (or key-derivation ::django-concat)
        primary-config {::algorithm algorithm ::salt salt ::key-derivation key-derivation}
        fallback-configs (for [fallback fallbacks]
                           {::algorithm (::algorithm fallback)
                            ::salt salt
                            ::key-derivation (or (::key-derivation fallback) key-derivation)})]
    (for [sig-config (cons primary-config fallback-configs)
          key private-keys]
      (signature-for sig-config to-sign key))))

;; --- URL-safe payload encoding (with optional zlib compression) ---

(defn- url-safe-payload-part
  "Encode payload for URL-safe serializer: JSON-encode, optionally compress,
   base64-encode.  If compressed, prefix with '.' (matching Python's
   URLSafeSerializer.dump_payload)."
  [payload]
  (let [json-bytes          (.getBytes (json/write-str payload) "UTF-8")
        [compressed? data]  (zlib/compress-if-beneficial json-bytes)
        b64                 (codec/b->b64 data)]
    (if compressed?
      (str "." b64)
      b64)))

(defn- extract-url-safe-payload
  "Decode payload from URL-safe serializer token.  If the payload part starts
   with '.', it's compressed: strip the prefix, base64-decode, decompress,
   then JSON-parse.  Otherwise just base64-decode and JSON-parse."
  ([payload-part]
   (extract-url-safe-payload payload-part nil))
  ([payload-part max-size]
   (let [compressed?  (.startsWith ^String payload-part ".")
         actual-part  (if compressed? (subs payload-part 1) payload-part)
         decoded      (codec/b64->b actual-part)
         json-bytes   (if compressed?
                        (if (and max-size (pos? max-size))
                          (zlib/decompress decoded max-size)
                          (zlib/decompress decoded))
                        decoded)]
     (json/read-str (String. ^bytes json-bytes "UTF-8")))))

;; --- Sign and verify ---

(defn sign
  "Run the signature process for a payload, yields token as a string.

  Needs at least `::algorithm`, `::salt`, `::private-key`, and `::payload`.
   `::algorithm`, `::salt`, and `::private-key` are shared knowledge elements.

   `::signer-type` controls the token format:
   - `::signer`                   (untimed, raw payload)
   - `::timestamp-signer`         (timed, raw payload) — default
   - `::url-safe-serializer`      (untimed, JSON payload, optional zlib compression)
   - `::url-safe-timed-serializer` (timed, JSON payload, optional zlib compression)

   `::key-derivation` defaults to `::django-concat`.
   `::timestamp` defaults to the UNIX epoch in seconds."
  ([{::keys [algorithm salt key-derivation signer-type timestamp payload private-key]
     :or    {algorithm      ::hmac-sha1
             key-derivation ::django-concat
             signer-type    ::timestamp-signer
             timestamp      (epoch)}
     :as    config}]
   (ex/assert-spec-valid ::sign-input config)
   (let [to-sign (case signer-type
                   ::signer
                   payload

                   ::timestamp-signer
                   (str payload "." (codec/int->b64 timestamp))

                   ::url-safe-serializer
                   (url-safe-payload-part payload)

                   ::url-safe-timed-serializer
                   (str (url-safe-payload-part payload)
                        "."
                        (codec/int->b64 timestamp)))]
     (str to-sign "." (signature-for config to-sign private-key))))
  ([config payload]
   (sign (assoc config ::payload payload)))
  ([config payload timestamp]
   (sign (assoc config ::payload payload ::timestamp timestamp))))

(defn verify
  "Run verification on a token, throwing if the signature is invalid
   or if the token's validity has expired. Yields the payload upon success.

   Needs at least `::algorithm`, `::salt`, `::private-keys`, and `::token`.
   `::signer-type` defaults to `::timestamp-signer`.
   `::key-derivation` defaults to `::django-concat`.

   Optionally accepts `::max-age`, in which case token validity in time will be
   checked.  Tokens whose timestamp is more than 60 seconds in the future are
   rejected as well, to tolerate clock skew between emitter and verifier."
  ([{::keys [token algorithm salt key-derivation signer-type max-age max-decompressed-size]
     :or    {algorithm      ::hmac-sha1
             key-derivation ::django-concat
             signer-type    ::timestamp-signer}
     :as    config}]
   (ex/assert-spec-valid ::verify-input config)
   (let [{::keys [payload-part timestamp-part timestamp to-sign signature]} (parse-token token signer-type)]
     (when (or (not (nat-int? timestamp))
               (<= Integer/MAX_VALUE timestamp))
       (ex/ex-forbidden! "invalid timestamp"))
     (when-not (some (partial comp/=== signature)
                     (signatures-for config to-sign))
       (ex/ex-forbidden! "invalid signature"))
     (let [age (- (epoch) timestamp)]
       (when (and (some? max-age)
                  (or (< age -60)
                      (< max-age age)))
         (ex/ex-forbidden! "token validity expired")))
     (case signer-type
       ::signer
       payload-part

       ::timestamp-signer
       payload-part

       ::url-safe-serializer
       (extract-url-safe-payload payload-part max-decompressed-size)

       ::url-safe-timed-serializer
       (extract-url-safe-payload payload-part max-decompressed-size))))
  ([config token]
   (verify (assoc config ::token token)))
  ([config token max-age]
   (verify (assoc config ::token token ::max-age max-age))))
