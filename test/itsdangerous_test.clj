(ns itsdangerous-test
  (:require [clojure.test :refer :all]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            itsdangerous
            [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.sign.util :as util]
            [cheshire.core :as json]))

(def secret "test")

(defn- unsign-exp-succ
  ([signed candidate]
   (unsign-exp-succ signed candidate nil))
  ([signed candidate opts]
   (is (bytes/equals? (itsdangerous/unsign signed secret opts)
                      (codecs/to-bytes candidate)))))

(defn- unsign-exp-fail
  ([signed cause]
   (unsign-exp-fail signed cause nil))
  ([signed cause opts]
   (try
     (itsdangerous/unsign signed secret opts)
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= cause (:cause (ex-data e))))))))

(deftest itsdangerous-wrong-key
  (let [candidate "foo bar "
        result    (itsdangerous/sign candidate "key" {:alg :hs1})]
    (unsign-exp-fail result :signature)))

(deftest itsdangerous-simple-unsign
  (is (bytes/equals? (codecs/to-bytes (json/generate-string [1 2 3 4]))
                     (itsdangerous/unsign "WzEsMiwzLDRd.X9jM62WJ1vHLTock5MeU_bwqh2A" "secret-key" {:alg :hs1})))
  (is (bytes/equals? (codecs/to-bytes (json/generate-string [1 2 3 4]))
                     (itsdangerous/unsign "WzEsMiwzLDRd.XE7MSg.flZqEQNN7jpDpwF3BYK3NeWEAus" "secret-key" {:alg :hs1}))))

(deftest itsdangerous-simple-sign
  (is (= "WzEsMiwzLDRd.X9jM62WJ1vHLTock5MeU_bwqh2A"
         (itsdangerous/sign (json/generate-string [1 2 3 4]) "secret-key" {:alg :hs1})))
  (is (= "WzEsMiwzLDRd.XE7MSg.flZqEQNN7jpDpwF3BYK3NeWEAus"
         (itsdangerous/sign (json/generate-string [1 2 3 4]) "secret-key" {:alg :hs1 :timestamp (long 1548667978)}))))

(deftest itsdangerous-outdated-sign
  (let [candidate "foo bar "
        result    (itsdangerous/sign candidate secret {:alg :hs1 :timestamp (dec (util/now))})]

    (unsign-exp-fail result :timestamp {:max-age 0})))

(defspec itsdangerous-spec-alg-hs 500
  (props/for-all
   [key  (gen/one-of [gen/bytes gen/string])
    data (gen/one-of [gen/bytes gen/string])
    alg  (gen/elements [:hs1])]
   (let [res1 (itsdangerous/sign data key {:alg alg})
         res2 (itsdangerous/unsign res1 key {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec itsdangerous-timed-spec-alg-hs 500
  (props/for-all
   [key  (gen/one-of [gen/bytes gen/string])
    data (gen/one-of [gen/bytes gen/string])
    alg  (gen/elements [:hs1])]
   (let [res1 (itsdangerous/sign data key {:alg alg :timestamp (util/now)})
         res2 (itsdangerous/unsign res1 key {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))
