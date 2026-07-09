(ns exoscale.itsdangerous
  "ItsDangerous signed token implementation.

   This namespace provides two main signatures: `sign` and `verify`,
   refer to their documentation for details. ItsDangerous uses a simple
   HMAC-based scheme to sign credentials. It is widely used in the Python
   world, especially in Flask applications.

   See https://itsdangerous.palletsprojects.com/ for more details."
  (:require [exoscale.ex                 :as ex]
            [clojure.data.json           :as json]
            [constance.comp              :as comp]
            [exoscale.itsdangerous.hmac  :as hmac]
            [exoscale.itsdangerous.codec :as codec]
            [exoscale.itsdangerous.spec  :as spec]))

(defn epoch
  "UNIX epoch in seconds"
  []
  (quot (System/currentTimeMillis) 1000))

(defn parse-token
  "Split a ItsDangerous token into its constituent parts.  Returns the
   raw payload part, optional timestamp part, parsed timestamp, the
   string to sign, and the signature."
  [s]
  (try
    (if-let [[_ payload-part timestamp-part signature] (re-matches spec/token-pattern s)]
      {::payload-part   payload-part
       ::timestamp-part timestamp-part
       ::timestamp      (if (some? timestamp-part) (codec/b64->int timestamp-part) 0)
       ::to-sign        (cond-> payload-part (some? timestamp-part) (str "." timestamp-part))
       ::signature      signature}
      (ex/ex-incorrect! "wrong token format" {::token s}))
    (catch Exception e
      (ex/ex-incorrect! "error while processing token" {::token s} e))))

(defn main-key
  "Figure out which private-key to use from the config.
   Support either a single `::private-key` for backward compatibility,
   or a collection of keys, in which case the first is selected."
  [{::keys [private-keys private-key]}]
  (or (first private-keys) private-key))

(defn signature-for
  "Compute the signature of a to-sign string. Yields the signature in Base64.

   Uses the configured algorithm, salt, and key derivation method."
  [{::keys [algorithm salt key-derivation] :as config} to-sign private-key]
  (let [key-derivation (or key-derivation ::django-concat)
        derived-key    (hmac/derive-key algorithm key-derivation private-key salt)]
    (codec/b->b64 (hmac/hmac-sign algorithm to-sign derived-key))))

(defn signatures-for
  "Yield all possible signatures for a to-sign string, based on the config."
  [{::keys [algorithm salt key-derivation private-keys private-key] :as config} to-sign]
  (if (empty? private-keys)
    [(signature-for config to-sign private-key)]
    (for [key private-keys]
      (signature-for config to-sign key))))

(defn sign
  "Run the signature process for a payload, yields token as a string.

   Needs at least `::algorithm`, `::salt`, `::private-key`, and `::payload`.
   `::algorithm`, `::salt`, and `::private-key` are shared knowledge elements.

   `::signer-type` controls the token format:
   - `::signer`                  (untimed, raw payload)
   - `::timestamp-signer`        (timed, raw payload) — default
   - `::url-safe-serializer`     (untimed, JSON payload)
   - `::url-safe-timed-serializer` (timed, JSON payload)

   `::key-derivation` defaults to `::django-concat`.
   `::timestamp` defaults to the UNIX epoch in seconds.
   If `::private-keys` is provided instead of `::private-key`, the first key
   in the collection is used to sign the payload."
  ([{::keys [algorithm salt key-derivation signer-type timestamp payload]
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
                   (codec/s->b64 (json/write-str payload))

                   ::url-safe-timed-serializer
                   (str (codec/s->b64 (json/write-str payload))
                        "."
                        (codec/int->b64 timestamp)))]
     (str to-sign "." (signature-for config to-sign (main-key config)))))
  ([config payload]
   (sign (assoc config ::payload payload)))
  ([config payload timestamp]
   (sign (assoc config ::payload payload ::timestamp timestamp))))

(defn verify
  "Run verification on a token, throwing if the signature is invalid
   or if the token's validity has expired. Yields the payload upon success.

   Needs at least `::algorithm`, `::salt`, `::private-key`, and `::token`.
   `::signer-type` defaults to `::timestamp-signer`.
   `::key-derivation` defaults to `::django-concat`.

   Optionally accepts `::max-age`, in which case token validity in time will be
   checked."
  ([{::keys [token algorithm salt key-derivation signer-type max-age private-key]
     :or    {algorithm      ::hmac-sha1
             key-derivation ::django-concat
             signer-type    ::timestamp-signer}
     :as    config}]
   (ex/assert-spec-valid ::verify-input config)
   (let [{::keys [payload-part timestamp-part timestamp to-sign signature]} (parse-token token)]
     (when-not (some (partial comp/=== signature)
                     (signatures-for config to-sign))
       (ex/ex-forbidden! "invalid signature"))
     (when (and (some? max-age)
                (< max-age (- (epoch) timestamp)))
       (ex/ex-forbidden! "token validity expired"))
     (case signer-type
       ::signer
       payload-part

       ::timestamp-signer
       payload-part

       ::url-safe-serializer
       (json/read-str (codec/b64->s payload-part))

       ::url-safe-timed-serializer
       (json/read-str (codec/b64->s payload-part)))))
  ([config token]
   (verify (assoc config ::token token)))
  ([config token max-age]
   (verify (assoc config ::token token ::max-age max-age))))
