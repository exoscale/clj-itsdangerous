(ns exoscale.itsdangerous-test
  (:require [clojure.test          :refer :all]
            [itsdangerous]
            [exoscale.itsdangerous :as danger]))

(deftest readme-test
  ;; Replicate usage shown in the README
  (let [payload     "{\"user-id\": 1234}"
        private-key "A-SECRET-KEY"
        salt        "session"
        algorithm   ::danger/hmac-sha1
        token       (danger/sign {:exoscale.itsdangerous/algorithm   algorithm
                                  :exoscale.itsdangerous/private-key private-key
                                  :exoscale.itsdangerous/salt        salt
                                  :exoscale.itsdangerous/payload     payload})]

    (testing "Verifying yields the initial payload"

      (is (= (danger/verify {:exoscale.itsdangerous/algorithm   algorithm
                             :exoscale.itsdangerous/private-key private-key
                             :exoscale.itsdangerous/salt        salt
                             :exoscale.itsdangerous/token       token})
             payload)))))

(deftest multiple-key-test
  ;; Replicate usage shown in the README
  (let [payload      "{\"user-id\": 1234}"
        old-key      "A-SECRET-KEY"
        private-keys ["ANOTHER-KEY" old-key]
        salt         "session"
        algorithm    ::danger/hmac-sha1
        token        (danger/sign {:exoscale.itsdangerous/algorithm   algorithm
                                   :exoscale.itsdangerous/private-key old-key
                                   :exoscale.itsdangerous/salt        salt
                                   :exoscale.itsdangerous/payload     payload})]

    (testing "Verifying yields the initial payload"

      (is (= (danger/verify {:exoscale.itsdangerous/algorithm    algorithm
                             :exoscale.itsdangerous/private-keys private-keys
                             :exoscale.itsdangerous/salt         salt
                             :exoscale.itsdangerous/token        token})
             payload)))))

(deftest compatibility-test
  (is (= (danger/verify {::danger/algorithm   ::danger/hmac-sha1
                         ::danger/private-key "A-SECRET-KEY"
                         ::danger/salt        "session"
                         ::danger/token       "SEVMTE8.nppGBrCjzE0Ipz1pzm6gRLwi_rc"})
         (itsdangerous/unsign "SEVMTE8.nppGBrCjzE0Ipz1pzm6gRLwi_rc"
                              "A-SECRET-KEY"
                              {:alg :hs1
                               :salt "session"})
         "HELLO")))
