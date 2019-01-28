(ns itsdangerous.core
  "ItsDangerous Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.hash :as hash]
            [buddy.core.mac :as mac]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [cheshire.core :as json])
  (:import org.bouncycastle.crypto.macs.HMac))

;; https://github.com/funcool/buddy-core/issues/58
(defmethod mac/engine :hmac+sha1
  [options]
  (let [digest (hash/resolve-digest-engine
                (:digest options :sha1))]
    (assert digest "Invalid digest engine.")
    (HMac. digest)))

(def +signers-map+
  "Supported algorithms."
  {:hs1 {:signer   #(mac/hash %1 {:alg :hmac+sha1 :key %2})
         :verifier #(mac/verify %1 %2 {:alg :hmac+sha1 :key %3})}})

(defn- encode-payload
  [payload]
  (-> payload
      (b64/encode true)
      (codecs/bytes->str)))

(defn- decode-payload
  [payload]
  (b64/decode payload))

(defn- derive-key
  "This method is called to devie the key. Use large random secret keys."
  [{:keys [key alg salt]}]
  (let [signer (get-in +signers-map+ [alg :signer])]
    (signer salt key)))

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [{:keys [alg payload] :as args}]
  (let [signer (get-in +signers-map+ [alg :signer])
        dkey    (derive-key args)]
    (encode-payload (signer payload dkey))))

(defn- split-itsdangerous-message
  [message]
  (str/split message #"\." 3))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [{:keys [alg signature timestamp payload] :as args}]
  (let [verifier  (get-in +signers-map+ [alg :verifier])
        dkey      (derive-key args)
        signature (b64/decode signature)
        payload'  (if timestamp
                    (str/join "." [payload timestamp])
                    payload)]
    (verifier payload' signature dkey)))

(defn- truncate
  [xs start end]
  (byte-array
   (for [i (range start end)]
     (aget xs i))))

(defn- timed-sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg salt timestamp] :or {alg :hs1 salt "itsdangerous"} :as opts}]]
  {:pre [payload]}
  (let [payload   (encode-payload payload)
        ts        (-> (or timestamp (util/now))
                      (codecs/long->bytes)
                      (truncate 4 8)
                      (encode-payload))
        payload'  (str/join "." [payload ts])
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :salt salt
                                        :payload payload'})]
    (str/join "." [payload' signature])))

(defn sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg salt timestamp] :or {alg :hs1 salt "itsdangerous"} :as opts}]]
  {:pre [payload]}
  (if timestamp
    (timed-sign payload pkey opts)
    (let [payload (encode-payload payload)
          signature (calculate-signature {:key pkey
                                          :alg alg
                                          :salt salt
                                          :payload payload})]
      (str/join "." [payload signature]))))

(defn unsign
  "Given a signed message, verify it and return
  the decoded payload."
  ([input pkey {:keys [alg salt max-age] :or {alg :hs1 salt "itsdangerous"}}]
   (let [[payload ts signature] (split-itsdangerous-message input)
         [ts signature]         (if signature [ts signature] [nil ts])]
     (when-not
      (try
        (verify-signature {:key       pkey
                           :signature signature
                           :alg       alg
                           :salt      salt
                           :timestamp ts
                           :payload   payload})
        (catch java.security.SignatureException se
          (throw (ex-info "Message seems corrupt or manipulated."
                          {:type :validation :cause :signature}
                          se))))
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature})))
     (when max-age
       (when-not ts
         (throw (ex-info "Timestamp is missing."
                         {:type :validation :cause :timestamp})))
       (let [timestamp (->> ts
                            (b64/decode)
                            (concat [0 0 0 0])
                            (byte-array)
                            (codecs/bytes->long))
             age       (- (util/now) (or timestamp 0))]
         (when (> age max-age)
           (throw (ex-info (format "Message seems expired %d > %d seconds." age max-age)
                           {:type :validation :cause :timestamp})))))
     (decode-payload payload))))

