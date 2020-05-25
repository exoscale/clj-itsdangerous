(ns exoscale.itsdangerous.hmac
  "JavaSE based implementation of hashed based message
   authentication."
  (:require [exoscale.ex :as ex])
  (:import javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(defn sha
  "Compute the HMAC of a payload, given a secret-key and
   supported algorithm."
  [hmac-type raw-input secret-string]
  (let [secret (if (string? secret-string)
                 (.getBytes (str secret-string))
                 secret-string)
        input  (if (string? raw-input)
                 (.getBytes (str raw-input))
                 raw-input)
        key    (SecretKeySpec. ^bytes secret (str hmac-type))]
    (-> (doto (Mac/getInstance (str hmac-type)) (.init key))
        (.doFinal ^bytes input))))

(def supported-algorithms
  "Known signing algorithms."
  {:exoscale.itsdangerous/hmac-sha1   (partial sha "HmacSHA1")
   :exoscale.itsdangerous/hmac-sha256 (partial sha "HmacSHA256")})

(defn by-algorithm
  "Retrieve signing function by algorithm, throws when an
   unsupported algorithm is requested."
  [algorithm]
  (or (get supported-algorithms algorithm)
      (ex/ex-not-found! (str "unknown algorithm: " algorithm))))
