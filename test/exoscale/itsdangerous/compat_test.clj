(ns exoscale.itsdangerous.compat-test
  "Compatibility tests against Python itsdangerous 2.2.0.

   These tests call a Python script via ``uv run`` that generates and
   verifies tokens for every supported signer/algorithm/key-derivation
   combination.  Two directions are exercised:

     Python -> Clojure -- tokens produced by Python are verified by clj-itsdangerous
     Clojure -> Python -- tokens produced by clj-itsdangerous are verified by Python

   Every combination must succeed in both directions."
  (:require [clojure.test          :refer :all]
            [clojure.java.shell    :as sh]
            [clojure.data.json     :as json]
            [exoscale.itsdangerous :as danger]))

(def ^:private python-project "test/python")
(def ^:private python-script  "test/python/compat.py")

(def ^:private secret  "secret-key")
(def ^:private salt     "cookie-session")
(def ^:private payload  "my-payload")

(def ^:private algorithm-map
  {"sha1"   ::danger/hmac-sha1
   "sha256" ::danger/hmac-sha256
   "sha512" ::danger/hmac-sha512})

(def ^:private signer-type-map
  {"Signer"                 ::danger/signer
   "TimestampSigner"        ::danger/timestamp-signer
   "URLSafeSerializer"      ::danger/url-safe-serializer
   "URLSafeTimedSerializer" ::danger/url-safe-timed-serializer})

(def ^:private key-derivation-map
  {"hmac"          ::danger/hmac
   "concat"        ::danger/concat
   "django-concat" ::danger/django-concat})

(defn- run-python
  "Invoke ``compat.py`` and return parsed JSON output."
  [command & [input]]
  (let [base-args ["uv" "run" "--project" python-project "python" python-script command]
        result (if input
                 (apply sh/sh (conj base-args :in input))
                 (apply sh/sh base-args))]
    (when-not (zero? (:exit result))
      (throw (ex-info "Python compatibility script failed"
                      {:command command
                       :exit    (:exit result)
                       :out     (:out result)
                       :err     (:err result)})))
    (json/read-str (:out result) :key-fn keyword)))

(defn- python-tokens
  []
  (run-python "generate"))

(defn- python-verify
  [token algorithm key-derivation signer-type]
  (run-python "verify"
              (json/write-str {:token          token
                               :secret         secret
                               :salt           salt
                               :algorithm      algorithm
                               :key_derivation key-derivation
                               :signer         signer-type})))

(defn- label
  [spec]
  (str (:signer spec) " "
       (:algorithm spec) " "
       (:key_derivation spec)))

(deftest python-to-clojure-compatibility
  (doseq [spec (python-tokens)]
    (testing (str "Python -> Clojure: " (label spec))
      (let [config {::danger/algorithm      (algorithm-map (:algorithm spec))
                    ::danger/key-derivation (key-derivation-map (:key_derivation spec))
                    ::danger/signer-type    (signer-type-map (:signer spec))
                    ::danger/private-keys [(:secret spec)]
                    ::danger/salt           (:salt spec)
                    ::danger/token          (:token spec)}
            result (try
                     (danger/verify config)
                     (catch Exception e
                       {:error (.getMessage e)}))]
        (is (not (map? result))
            (str "verification threw: " (:error result)))
        (when-not (map? result)
          (is (= (:payload spec) result)
              (str "payload mismatch: expected " (pr-str (:payload spec))
                   ", got " (pr-str result))))))))

(def ^:private large-payload (apply str (repeat 200 "x")))

(defn- python-compressed-tokens
  []
  (run-python "generate-compressed"))

(deftest python-to-clojure-compressed-compatibility
  (doseq [spec (python-compressed-tokens)]
    (testing (str "Python -> Clojure (compressed): " (label spec))
      (is (:compressed spec)
          "Python should have produced a compressed token")
      (let [config {::danger/algorithm      (algorithm-map (:algorithm spec))
                    ::danger/key-derivation (key-derivation-map (:key_derivation spec))
                    ::danger/signer-type    (signer-type-map (:signer spec))
                    ::danger/private-keys [(:secret spec)]
                    ::danger/salt           (:salt spec)
                    ::danger/token          (:token spec)}
            result (try
                     (danger/verify config)
                     (catch Exception e
                       {:error (.getMessage e)}))]
        (is (not (map? result))
            (str "verification threw: " (:error result)))
        (when-not (map? result)
          (is (= (:payload spec) result)
              (str "payload mismatch: expected " (pr-str (:payload spec))
                   ", got " (pr-str result))))))))

(deftest clojure-to-python-compressed-compatibility
  (doseq [algorithm ["sha1" "sha256" "sha512"]
          signer    ["URLSafeSerializer" "URLSafeTimedSerializer"]
          key-derivation ["hmac" "concat" "django-concat"]]
    (testing (str "Clojure -> Python (compressed): " signer " " algorithm " " key-derivation)
      (let [clj-token (danger/sign {::danger/algorithm      (algorithm-map algorithm)
                                    ::danger/key-derivation (key-derivation-map key-derivation)
                                    ::danger/signer-type    (signer-type-map signer)
                                    ::danger/private-key secret
                                    ::danger/salt           salt
                                    ::danger/payload        large-payload})
            ;; Verify the token is actually compressed (payload part starts with ".")
            _           (is (-> clj-token
                                (.startsWith "."))
                            (str "token should be compressed: " (pr-str clj-token)))
            result      (python-verify clj-token algorithm key-derivation signer)]
        (is (:valid result)
            (str "Python verification failed: " result))
        (when (:valid result)
          (is (= large-payload (:payload result))
              (str "payload mismatch: expected " (pr-str large-payload)
                   ", got " (pr-str (:payload result)))))))))
