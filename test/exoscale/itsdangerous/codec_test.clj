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

(deftest bytes->int-rejects-oversized-input
  (let [ex (try
             (codec/bytes->int (byte-array (range 9)))
             (catch Exception e e))]
    (is (not (nil? ex)) "should have thrown")
    (is (= :exoscale.itsdangerous/invalid-timestamp (:type (ex-data ex))))))

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

(deftest verify-rejects-oversized-timestamp
  (let [config {::danger/algorithm      ::danger/hmac-sha1
                ::danger/key-derivation ::danger/django-concat
                ::danger/signer-type    ::danger/timestamp-signer
                ::danger/private-keys   ["secret"]
                ::danger/salt           "salt"
                ;; AAAAAAAAAAAA is base64url of 9 zero bytes (> 8 bytes)
                ::danger/token          "payload.AAAAAAAAAAAA.invalidsignature"}
        ex (try (danger/verify config)
                (catch Exception e e))]
    (is (not (nil? ex)) "should have thrown")
    (is (= :exoscale.ex/forbidden (:type (ex-data ex))))))

(deftest decompress-size-limit
  (let [large-payload (apply str (repeat 5000 "x"))
        base-config   {::danger/algorithm      ::danger/hmac-sha1
                       ::danger/key-derivation ::danger/django-concat
                       ::danger/signer-type    ::danger/url-safe-serializer
                       ::danger/private-key    "secret"
                       ::danger/salt           "salt"
                       ::danger/payload        large-payload}
        token         (danger/sign base-config)]
    (testing "decompression under limit succeeds"
      (let [result (danger/verify {::danger/algorithm              ::danger/hmac-sha1
                                   ::danger/key-derivation         ::danger/django-concat
                                   ::danger/signer-type            ::danger/url-safe-serializer
                                   ::danger/private-keys           ["secret"]
                                   ::danger/salt                   "salt"
                                   ::danger/token                  token
                                   ::danger/max-size  10000})]
        (is (= large-payload result))))
    (testing "decompression over limit throws"
      (let [ex (try
                 (danger/verify {::danger/algorithm              ::danger/hmac-sha1
                                 ::danger/key-derivation         ::danger/django-concat
                                 ::danger/signer-type            ::danger/url-safe-serializer
                                 ::danger/private-keys           ["secret"]
                                 ::danger/salt                   "salt"
                                 ::danger/token                  token
                                 ::danger/max-size  100})
                 (catch Exception e e))]
        (is (not (nil? ex)) "should have thrown")
        (is (= :exoscale.ex/forbidden (:type (ex-data ex))))))))

(deftest default-max-size-enforced
  (let [huge-payload (apply str (repeat 1100000 "x"))
        base-config  {::danger/algorithm      ::danger/hmac-sha1
                      ::danger/key-derivation ::danger/django-concat
                      ::danger/signer-type    ::danger/url-safe-serializer
                      ::danger/private-key    "secret"
                      ::danger/salt           "salt"
                      ::danger/payload        huge-payload}
        token        (danger/sign base-config)]
    (testing "default 1MB limit is enforced for decompression without explicit max-size"
      (let [ex (try
                 (danger/verify {::danger/algorithm      ::danger/hmac-sha1
                                 ::danger/key-derivation ::danger/django-concat
                                 ::danger/signer-type    ::danger/url-safe-serializer
                                 ::danger/private-keys   ["secret"]
                                 ::danger/salt           "salt"
                                 ::danger/token          token})
                 (catch Exception e e))]
        (is (not (nil? ex)) "should have thrown")
        (is (= :exoscale.ex/forbidden (:type (ex-data ex))))))))

(deftest default-max-size-enforced-for-raw-token
  (let [huge-payload (apply str (repeat 1100000 "x"))
        base-config  {::danger/algorithm      ::danger/hmac-sha1
                      ::danger/key-derivation ::danger/django-concat
                      ::danger/signer-type    ::danger/timestamp-signer
                      ::danger/private-key    "secret"
                      ::danger/salt           "salt"
                      ::danger/payload        huge-payload}
        token        (danger/sign base-config)]
    (testing "default 1MB limit is enforced for raw token size"
      (let [ex (try
                 (danger/verify {::danger/algorithm      ::danger/hmac-sha1
                                 ::danger/key-derivation ::danger/django-concat
                                 ::danger/signer-type    ::danger/timestamp-signer
                                 ::danger/private-keys   ["secret"]
                                 ::danger/salt           "salt"
                                 ::danger/token          token})
                 (catch Exception e e))]
        (is (not (nil? ex)) "should have thrown")
        (is (= :exoscale.ex/forbidden (:type (ex-data ex))))))))
