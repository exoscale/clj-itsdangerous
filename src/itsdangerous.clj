(ns itsdangerous
  "Provided for backward compatibility only.
   Please use `exoscale.itsdangerous`"
  (:require [exoscale.itsdangerous :as danger]))

(def known-algos
  "Known algorithms"
  {:hs1 ::danger/hmac-sha1})

(defn sign
  "Deprecated - please use `exoscale.itsdangerous/sign`"
  [payload pkey & [{:keys [alg salt timestamp]
                    :or   {alg :hs1 salt "itsdangerous"}
                    :as   opts}]]
  (danger/sign (cond-> {::danger/algorithm   (get known-algos alg alg)
                        ::danger/salt        salt
                        ::danger/private-key pkey
                        ::danger/payload     payload}
                 (some? timestamp)
                 (assoc ::danger/timestamp timestamp))))

(defn unsign
  "Deprecated - please use `exoscale.itsdangerous/verify`"
  [input pkey {:keys [alg salt max-age] :or {alg :hs1 salt "itsdangerous"}}]
  (danger/verify (cond-> {::danger/algorithm   (get known-algos alg alg)
                          ::danger/salt        salt
                          ::danger/private-key pkey
                          ::danger/token       input}
                   (some? max-age)
                   (assoc ::danger/max-age max-age))))
