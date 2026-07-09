(ns exoscale.itsdangerous.hmac
  "JavaSE based implementation of hashed based message
   authentication."
  (:require [exoscale.ex :as ex])
  (:import java.security.MessageDigest
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

;; Algorithm names
(defn hmac-algorithm-name
  "Get the HMAC algorithm name (e.g. 'HmacSHA1') for a given algorithm keyword."
  [algorithm]
  (case algorithm
    :exoscale.itsdangerous/hmac-sha1   "HmacSHA1"
    :exoscale.itsdangerous/hmac-sha256 "HmacSHA256"))

(defn hash-algorithm-name
  "Get the hash algorithm name (e.g. 'SHA-1') for a given algorithm keyword."
  [algorithm]
  (case algorithm
    :exoscale.itsdangerous/hmac-sha1   "SHA-1"
    :exoscale.itsdangerous/hmac-sha256 "SHA-256"))

(defn digest
  "Compute the hash of a byte array using the given algorithm."
  [algorithm ^bytes data]
  (let [hash-type (hash-algorithm-name algorithm)
        md (MessageDigest/getInstance (str hash-type))]
    (.digest md data)))

(defn hmac-sign
  "Compute the HMAC of a payload using the given algorithm and key."
  [algorithm raw-input derived-key]
  (let [payload (if (string? raw-input)
                  (.getBytes (str raw-input) "UTF-8")
                  raw-input)
        hmac-type (hmac-algorithm-name algorithm)
        key (SecretKeySpec. ^bytes derived-key (str hmac-type))]
    (-> (doto (Mac/getInstance (str hmac-type)) (.init key))
        (.doFinal ^bytes payload))))

(defn derive-key
  "Derive a key from secret and salt using the given algorithm and key derivation method.

   Supported methods:
   - :hmac          — HMAC(secret, salt)
   - :concat        — hash(salt + secret)
   - :django-concat — hash(salt + 'signer' + secret)"
  [algorithm key-derivation secret salt]
  (let [secret-bytes (if (string? secret)
                       (.getBytes ^String secret "UTF-8")
                       secret)
        salt-bytes (if (string? salt)
                     (.getBytes ^String salt "UTF-8")
                     salt)]
    (case key-derivation
      (:hmac :exoscale.itsdangerous/hmac)
      (hmac-sign algorithm salt-bytes secret-bytes)

      (:concat :exoscale.itsdangerous/concat)
      (let [data (byte-array (+ (count salt-bytes) (count secret-bytes)))]
        (System/arraycopy salt-bytes 0 data 0 (count salt-bytes))
        (System/arraycopy secret-bytes 0 data (count salt-bytes) (count secret-bytes))
        (digest algorithm data))

      (:django-concat :exoscale.itsdangerous/django-concat)
      (let [^String signer-str "signer"
            signer-bytes (.getBytes signer-str "UTF-8")
            total-len (+ (count salt-bytes) (count signer-bytes) (count secret-bytes))
            data (byte-array total-len)]
        (System/arraycopy salt-bytes 0 data 0 (count salt-bytes))
        (System/arraycopy signer-bytes 0 data (count salt-bytes) (count signer-bytes))
        (System/arraycopy secret-bytes 0 data (+ (count salt-bytes) (count signer-bytes)) (count secret-bytes))
        (digest algorithm data))

      (ex/ex-not-found! (str "unknown key derivation: " key-derivation)))))
