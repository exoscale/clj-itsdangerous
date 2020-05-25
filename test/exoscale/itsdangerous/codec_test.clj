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
