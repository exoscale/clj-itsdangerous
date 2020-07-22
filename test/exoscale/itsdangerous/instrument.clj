(ns exoscale.itsdangerous.instrument
  (:require [clojure.test                    :refer :all]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators   :as gen]
            [clojure.test.check.properties   :as prop]
            [clojure.spec.alpha              :as s]
            [clojure.spec.test.alpha         :as stest]
            [exoscale.itsdangerous           :as danger]
            exoscale.itsdangerous.spec))

(def parse-token-overrides
  {::danger/token #(gen/fmap
                    (partial apply danger/sign)
                    (s/gen (s/tuple ::danger/config ::danger/payload)))})

(deftest parse-token-test
  (is
   (empty?
    (for [res (stest/check `danger/parse-token
                           {:gen parse-token-overrides})
          :let [abbrev (stest/abbrev-result res)]
          :when (some? (:failure abbrev))]
      abbrev))))

(deftest signature-for-test
  (is
   (empty?
    (for [res (stest/check `danger/signature-for)
          :let [abbrev (stest/abbrev-result res)]
          :when (some? (:failure abbrev))]
      abbrev))))

(deftest signatures-for-test
  (is
   (empty?
    (for [res (stest/check `danger/signatures-for)
          :let [abbrev (stest/abbrev-result res)]
          :when (some? (:failure abbrev))]
      abbrev))))

(deftest main-key-test
  (is
   (empty?
    (for [res (stest/check `danger/main-key)
          :let [abbrev (stest/abbrev-result res)]
          :when (some? (:failure abbrev))]
      abbrev))))

(deftest epoch-test
  (is
   (empty?
    (for [res (stest/check `danger/epoch)
          :let [abbrev (stest/abbrev-result res)]
          :when (some? (:failure abbrev))]
      abbrev))))
