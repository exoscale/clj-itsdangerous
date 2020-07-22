(ns exoscale.itsdangerous
  "ItsDangerous signed token implementation. This namespace provides two main
   signatures: `sign` and `verify`, refer to their documentation for details.
   ItsDangerous uses a simple hmac-based scheme to sign credentials. It is
   widely used in the Python world, especially in Flask applications.
   See https://itsdangerous.palletsprojects.com/en/1.1.x/ for more details.

   ItsDangerous revolves around tuples of `[payload, timestamp, signature]`
   or the untimed `[payload, signature]` alternative. In its URL safe variant,
   each element of the tuple is Base64 encoded. This is the only variant
   supported in this implementation.

   When signing and verifying, ItsDangerous supports the addition of a somewhat
   misnamed *salt*, used to namespace signing. In this case, the key is derived
   by first hashing the salt. The derived key is then used to sign or verify
   payloads.

   Knowledge that should be shared out-of-band between signers and verifiers:

     - A secret key (K)
     - A salt for namespacing (S)
     - The selected hashing algorithm (A) (with functions HASH_A and HMAC_A)

   For a payload P at timestamp T, signing consists of:

       TOSIGN = T ? (B64(P) + '.' + B64(T)) : (B64(P))
       B64(P) + TOSIGN + '.' + B64(HMAC_A(HASH_A(K, S), TOSIGN))"
  (:require [exoscale.ex                 :as ex]
            [constance.comp              :as comp]
            [exoscale.itsdangerous.hmac  :as hmac]
            [exoscale.itsdangerous.codec :as codec]
            [exoscale.itsdangerous.spec  :as spec]))

(defn epoch
  "UNIX epoch in seconds"
  []
  (quot (System/currentTimeMillis) 1000))

(defn parse-token
  "Split a ItsDangerous token into its constituent parts. Assume timestamp to
   be 0 when not provided. The string to sign is returned as well."
  [s]
  (try
    (if-let [[_ payload timestamp signature] (re-matches spec/token-pattern s)]
      {::payload   (codec/b64->s payload)
       ::timestamp (if (some? timestamp) (codec/b64->int timestamp) 0)
       ::to-sign   (cond-> payload (some? timestamp) (str "." timestamp))
       ::signature signature}
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
  "Given a supported algorithm (`::hmac-sha1` `::hmac-sha256`), private key, and
   salt, compute the signature of a payload. Yields the signature in Base64."
  [{::keys [algorithm salt] :as config} payload private-key]
  (let [signer (hmac/by-algorithm algorithm)]
    (->> (signer salt private-key)
         (signer payload)
         (codec/b->b64))))

(defn signatures-for
  "Yield all possible signatures for a payload, based on the config"
  [{::keys [algorithm private-keys salt] :as config} payload]
  (if (empty? private-keys)
    [(signature-for config payload (::private-key config))]
    (for [private-key private-keys]
      (signature-for config payload private-key))))

(defn sign
  "Run the signature process for a payload, yields token as a string.

   Needs at least `::algorithm`, `::salt`, `::private-key`, and `::payload`.
   `::algorithm`, `::salt`, and `::private-key` are shared knowledge elements,
   to be agreed upon out-of-band, `::payload`, the payload to sign as a string.
   If `::private-keys` is provided instead of `::private-key`, the first key
   in the collection is used to sign the payload.

   Optionally accepts `::timestamp`, defaulting to the UNIX epoch in seconds."
  ([{::keys [algorithm salt timestamp payload]
     :or    {algorithm ::hmac-sha1
             timestamp (epoch)}
     :as    config}]
   (ex/assert-spec-valid ::sign-input config)
   (let [to-sign (str (codec/s->b64 payload) "." (codec/int->b64 timestamp))]
     (str to-sign "." (signature-for config to-sign (main-key config)))))
  ([config payload]
   (sign (assoc config ::payload payload)))
  ([config payload timestamp]
   (sign (assoc config ::payload payload ::timestamp timestamp))))

(defn verify
  "Run verification on a token, throwing if the signature is invalid
   or if the token's validity has expired. Yields the payload upon success.

   Needs at least `::algorithm`, `::salt`, `::private-key`, and `::token`.
  `::algorithm`, `::salt`, and `::private-key` are shared knowledge elements,
   to be agreed upon out-of-band, `::token`, the token to verify.

   Optionally accepts `::max-age`, in which case token validity in time will be
   checked."
  ([{::keys [token algorithm salt max-age private-key]
     :or    {algorithm ::hmac-sha1}
     :as    config}]
   (ex/assert-spec-valid ::verify-input config)
   (let [{::keys [to-sign payload timestamp signature]} (parse-token token)]
     (when-not (some (partial comp/=== signature)
                     (signatures-for config to-sign))
       (ex/ex-forbidden! "invalid signature"))
     (when (and (some? max-age)
                (< max-age (- (epoch) timestamp)))
       (ex/ex-forbidden! "token validity expired"))
     payload))
  ([config token]
   (verify (assoc config ::token token)))
  ([config token max-age]
   (verify (assoc config ::token token ::max-age max-age))))
