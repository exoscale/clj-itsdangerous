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
(s/def ::d/algorithm    #{::d/hmac-sha1 ::d/hmac-sha256})
(s/def ::d/salt         (s/and string? (complement str/blank?)))
(s/def ::d/max-age      nat-int?)
(s/def ::d/token        (partial re-matches token-pattern))
(s/def ::d/timestamp    (s/and nat-int? #(< % Integer/MAX_VALUE)))
(s/def ::d/signature    (s/and string? (complement str/blank?)))
(s/def ::d/to-sign      string?)
(s/def ::d/parsed-token (s/keys :req [::d/payload ::d/timestamp
                                      ::d/signature ::d/to-sign]))
(s/def ::d/config       (s/keys :req [::d/private-key ::d/salt ::d/algorithm]))
(s/def ::d/verify-input (s/keys :req [::d/private-key ::d/salt
                                      ::d/algorithm ::d/token]
                                :opt [::d/max-age]))
(s/def ::d/sign-input   (s/keys :req [::d/private-key ::d/salt
                                      ::d/algorithm ::d/payload]
                                :opt [::d/timestamp]))
(s/def ::d/sigfor-input (s/keys :req [::d/private-key ::d/salt ::d/algorithm]))

(s/fdef d/verify
  :args (s/cat :opts ::d/verify-input)
  :ret  ::d/payload)

(s/fdef d/sign
  :args (s/cat :opts ::d/sign-input)
  :ret  ::d/token)

(s/fdef d/signature-for
  :args (s/cat :opts ::d/sigfor-input :payload ::d/payload)
  :ret  ::d/signature)

(s/fdef d/epoch
  :args (s/cat)
  :ret  ::d/timestamp)

(s/fdef d/parse-token
  :args (s/cat :input ::d/token)
  :ret  ::d/parsed-token)
