(ns exoscale.itsdangerous.spec
  (:require [clojure.spec.alpha :as s]
            [clojure.string     :as str]))

(create-ns 'exoscale.itsdangerous)
(alias 'd 'exoscale.itsdangerous)

(def token-pattern
  "Regexp for a valid itsdangerous token.  Must contain at least one dot
   separating the payload from the signature.  May start with a dot for
   compressed URL-safe serializer tokens or empty payloads."
  #"(?s).*\..+")

(s/def ::d/payload          any?)
(s/def ::d/sign-key
  (s/with-gen (complement nil?)
    #(s/gen (s/and string? (complement str/blank?)))))
(s/def ::d/verify-keys   (s/and (s/coll-of ::d/sign-key)
                                (complement empty?)))
(s/def ::d/algorithm        #{::d/hmac-sha1 ::d/hmac-sha256 ::d/hmac-sha512})
(s/def ::d/key-derivation   #{::d/hmac ::d/concat ::d/django-concat})
(s/def ::d/signer-type      #{::d/signer
                              ::d/timestamp-signer
                              ::d/url-safe-serializer
                              ::d/url-safe-timed-serializer})
(s/def ::d/salt             (s/and string? (complement str/blank?)))
(s/def ::d/max-age          nat-int?)
(s/def ::d/max-size         nat-int?)
(s/def ::d/token            (partial re-matches token-pattern))
(s/def ::d/timestamp        (s/and nat-int? #(< % Integer/MAX_VALUE)))
(s/def ::d/signature        (s/and string? (complement str/blank?)))
(s/def ::d/signatures       (s/coll-of ::d/signature))
(s/def ::d/to-sign          string?)
(s/def ::d/parsed-token     (s/keys :req [::d/payload-part ::d/timestamp
                                          ::d/signature ::d/to-sign]))
(s/def ::d/fallback         (s/keys :req [::d/algorithm]
                                    :opt [::d/key-derivation]))
(s/def ::d/fallbacks        (s/coll-of ::d/fallback))
(s/def ::d/config           (s/keys :req [::d/verify-keys
                                          ::d/salt
                                          ::d/algorithm]
                                    :opt [::d/key-derivation
                                          ::d/signer-type
                                          ::d/fallbacks]))
(s/def ::d/verify-input     (s/merge ::d/config
                                     (s/keys :req [::d/token]
                                             :opt [::d/max-size])))
(s/def ::d/sign-config      (s/keys :req [::d/sign-key
                                          ::d/salt
                                          ::d/algorithm]
                                    :opt [::d/key-derivation
                                          ::d/signer-type]))
(s/def ::d/sign-input       (s/merge ::d/sign-config
                                     (s/keys :req [::d/payload]
                                             :opt [::d/timestamp])))
(s/fdef d/verify
  :args (s/cat :config  ::d/config
               :token   (s/? ::d/token)
               :max-age (s/? ::d/max-age))
  :ret  ::d/payload)

(s/fdef d/sign
  :args (s/cat :config    ::d/sign-config
               :payload   (s/? ::d/payload)
               :timestamp (s/? ::d/timestamp))
  :ret  ::d/token)

(s/fdef d/parse-token
  :args (s/cat :input ::d/token :signer-type ::d/signer-type)
  :ret  ::d/parsed-token)
