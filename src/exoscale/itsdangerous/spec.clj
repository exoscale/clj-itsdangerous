(ns exoscale.itsdangerous.spec
  (:require [clojure.spec.alpha :as s]
            [clojure.string     :as str]))

(create-ns 'exoscale.itsdangerous)
(alias 'd 'exoscale.itsdangerous)

(def token-pattern
  "Regexp for a valid itsdangerous token"
  #"^([^.]*)\.(?:([^.]+)\.)?([^.]+)$")

(s/def ::d/payload      string?)
(s/def ::d/private-key  (s/and string? (complement str/blank?)))
(s/def ::d/private-keys (s/and  (s/coll-of ::d/private-key)
                                (complement empty?)))
(s/def ::d/algorithm    #{::d/hmac-sha1 ::d/hmac-sha256})
(s/def ::d/salt         (s/and string? (complement str/blank?)))
(s/def ::d/max-age      nat-int?)
(s/def ::d/token        (partial re-matches token-pattern))
(s/def ::d/timestamp    (s/and nat-int? #(< % Integer/MAX_VALUE)))
(s/def ::d/signature    (s/and string? (complement str/blank?)))
(s/def ::d/signatures   (s/coll-of ::d/signature))
(s/def ::d/to-sign      string?)
(s/def ::d/parsed-token (s/keys :req [::d/payload ::d/timestamp
                                      ::d/signature ::d/to-sign]))
(s/def ::d/config       (s/keys :req [(or ::d/private-key
                                          ::d/private-keys)
                                      ::d/salt
                                      ::d/algorithm]))
(s/def ::d/verify-input (s/merge ::d/config
                                 (s/keys :req [::d/token])))
(s/def ::d/sign-input   (s/merge ::d/config
                                 (s/keys :req [::d/payload]
                                         :opt [::d/timestamp])))
(s/fdef d/verify
  :args (s/cat :config  ::d/config
               :token   (s/? ::d/token)
               :max-age (s/? ::d/max-age))
  :ret  ::d/payload)

(s/fdef d/sign
  :args (s/cat :config    ::d/config
               :payload   (s/? ::d/payload)
               :timestamp (s/? ::d/timestamp))
  :ret  ::d/token)

(s/fdef d/main-key
  :args (s/cat :config ::d/config)
  :ret  ::d/private-key)

(s/fdef d/signature-for
  :args (s/cat :config ::d/config :payload ::d/payload :k ::d/private-key)
  :ret  ::d/signature)

(s/fdef d/signatures-for
  :args (s/cat :config ::d/config :payload ::d/payload)
  :ret  ::d/signatures)

(s/fdef d/epoch
  :args (s/cat)
  :ret  ::d/timestamp)

(s/fdef d/parse-token
  :args (s/cat :input ::d/token)
  :ret  ::d/parsed-token)
