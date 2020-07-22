(ns exoscale.itsdangerous.property-testing
  (:require [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators   :as gen]
            [clojure.test.check.properties   :as prop]
            [clojure.spec.alpha              :as s]
            [clojure.spec.test.alpha         :as stest]
            [exoscale.itsdangerous           :as danger]
            exoscale.itsdangerous.spec))

(stest/instrument `danger/sign)
(stest/instrument `danger/verify)
(stest/instrument `danger/parse-token)
(stest/instrument `danger/signature-for)
(stest/instrument `danger/main-key)

(defspec roundtrip-sign-to-verify
  10000
  (prop/for-all
   [config (s/gen ::danger/config)
    payload (s/gen ::danger/payload)]
   (let [token (danger/sign config payload)]
     (= payload (danger/verify config token)))))

(defspec token-validity-is-enforced
  10000
  (prop/for-all
   [config  (s/gen ::danger/config)
    payload (s/gen ::danger/payload)]
   (let [token (danger/sign config payload 0)]
     (= [:exoscale.ex/forbidden "token validity expired"]
        (try
          (danger/verify config token 86400)
          (catch Exception e
            [(:type (ex-data e)) (ex-message e)]))))))

(defspec token-validity-is-enforced-small-window
  10000
  (prop/for-all
   [config  (s/gen ::danger/config)
    payload (s/gen ::danger/payload)]
   (let [token (danger/sign config payload (dec (danger/epoch)))]
     (= [:exoscale.ex/forbidden "token validity expired"]
        (try
          (danger/verify config token 0)
          (catch Exception e
            [(:type (ex-data e)) (ex-message e)]))))))

(defspec token-signature-is-enforced-private-key-variant
  10000
  (prop/for-all
   [base        (s/gen ::danger/config)
    private-key (s/gen ::danger/private-key)
    payload     (s/gen ::danger/payload)]
   (let [good-config (assoc base ::danger/private-keys [private-key])
         bad-config  (assoc base ::danger/private-keys [(str private-key "f")])
         token       (danger/sign good-config payload)]
     (= [:exoscale.ex/forbidden "invalid signature"]
        (try
          (danger/verify  bad-config token)
          (catch Exception e
            [(:type (ex-data e)) (ex-message e)]))))))

(defspec token-signature-is-enforced-salt-variant
  10000
  (prop/for-all
   [config  (s/gen ::danger/config)
    payload (s/gen ::danger/payload)]
   (let [token (danger/sign config payload)]
     (= [:exoscale.ex/forbidden "invalid signature"]
        (try
          (danger/verify (update config ::danger/salt str "suffix") token)
          (catch Exception e
            [(:type (ex-data e)) (ex-message e)]))))))
