(ns exoscale.itsdangerous.codec-test
  (:require [clojure.test                    :refer :all]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators   :as gen]
            [clojure.test.check.properties   :as prop]
            [clojure.spec.alpha              :as s]
            [exoscale.itsdangerous           :as danger]
            [exoscale.itsdangerous.codec     :as codec]
            [exoscale.itsdangerous.spec]))

(defspec integer-conversion
  100000
  (prop/for-all
   [x (s/gen ::danger/timestamp)]
   (let [y (-> x codec/int->bytes codec/bytes->int)]
     (= x y))))

(deftest verify-rejects-out-of-range-timestamp
  (let [config {::danger/algorithm      ::danger/hmac-sha1
                ::danger/key-derivation ::danger/django-concat
                ::danger/signer-type    ::danger/timestamp-signer
                ::danger/private-keys   ["secret"]
                ::danger/salt           "salt"
                ;; gAAAAA is base64url of 0x80000000 = 2147483648 > Integer/MAX_VALUE
                ::danger/token          "payload.gAAAAA.invalidsignature"}
        ex (try (danger/verify config)
                (catch Exception e e))]
    (is (not (nil? ex)) "should have thrown")
    (is (= :exoscale.ex/forbidden (:type (ex-data ex))))))
