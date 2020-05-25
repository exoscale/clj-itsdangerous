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

(defspec roundtrip-sign-to-verify
  10000
  (prop/for-all
   [input (s/gen (s/keys :req [::danger/algorithm ::danger/payload
                               ::danger/private-key ::danger/salt]))]
   (let [token (danger/sign input)]
     (= (::danger/payload input)
        (danger/verify (-> input
                           (dissoc ::danger/payload)
                           (assoc ::danger/token token)))))))

(defspec token-validity-is-enforced
  10000
  (prop/for-all
   [input (s/gen (s/keys :req [::danger/algorithm ::danger/payload
                               ::danger/private-key ::danger/salt]))]
   (let [token (danger/sign (assoc input ::danger/timestamp 0))]
     (= [:exoscale.ex/forbidden "token validity expired"]
        (-> (try
              (danger/verify (-> input
                                 (dissoc ::danger/payload)
                                 (assoc ::danger/token token)
                                 (assoc ::danger/max-age 86400)))
              (catch Exception e
                [(:type (ex-data e)) (ex-message e)])))))))

(defspec token-validity-is-enforced-small-window
  10000
  (prop/for-all
   [input (s/gen (s/keys :req [::danger/algorithm ::danger/payload
                               ::danger/private-key ::danger/salt]))]
   (let [token (danger/sign
                (-> input
                    (assoc ::danger/timestamp (dec (danger/epoch)))))]
     (= [:exoscale.ex/forbidden "token validity expired"]
        (-> (try
              (danger/verify (-> input
                                 (dissoc ::danger/payload)
                                 (assoc ::danger/token token)
                                 (assoc ::danger/max-age 0)))
              (catch Exception e
                [(:type (ex-data e)) (ex-message e)])))))))

(defspec token-signature-is-enforced-private-key-variant
  10000
  (prop/for-all
   [input (s/gen (s/keys :req [::danger/algorithm ::danger/payload
                               ::danger/private-key ::danger/salt]))]
   (let [token (danger/sign input)]
     (= [:exoscale.ex/forbidden "invalid signature"]
        (-> (try
              (danger/verify (-> input
                                 (dissoc ::danger/payload)
                                 (assoc ::danger/token token)
                                 (update ::danger/private-key str "suffix")))
              (catch Exception e
                [(:type (ex-data e)) (ex-message e)])))))))

(defspec token-signature-is-enforced-salt-variant
  10000
  (prop/for-all
   [input (s/gen (s/keys :req [::danger/algorithm ::danger/payload
                               ::danger/private-key ::danger/salt]))]
   (let [token (danger/sign input)]
     (= [:exoscale.ex/forbidden "invalid signature"]
        (-> (try
              (danger/verify (-> input
                                 (dissoc ::danger/payload)
                                 (assoc ::danger/token token)
                                 (update ::danger/salt str "suffix")))
              (catch Exception e
                [(:type (ex-data e)) (ex-message e)])))))))
