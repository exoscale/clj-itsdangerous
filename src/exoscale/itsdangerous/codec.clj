(ns exoscale.itsdangerous.codec
  "Standard format coercers"
  (:require [clojure.string :as str])
  (:import java.util.Base64))

(defn ^String b->b64
  "Convert a byte array to URL encoded Base64. Padding ('=' chars) is stripped."
  [^bytes b]
  (-> (String. (.encode (Base64/getUrlEncoder) b))
      (str/replace #"=+$" "")))

(defn ^String s->b64
  "Convert a string to URL encoded Base64."
  [^String s]
  (b->b64 (.getBytes s "UTF-8")))

(defn b64->b
  "Decodes an URL encoded string to a byte array."
  [^String s]
  (.decode (Base64/getUrlDecoder) (.getBytes s)))

(defn ^String b64->s
  "Decodes an URL encoded string to a string."
  [^String s]
  (String. ^bytes (b64->b s) "UTF-8"))

(def bit-shifts
  "Bit shifts for integer conversions"
  [24 16 8 0])

(defn int->bytes
  "Convert an integer to a 4-wide byte array. This is
   used to store timestamps in ItsDangerous tokens. Since
   timestamps are 32-bit wide and represent seconds since
   the UNIX epoch, please consider another solution
   if you want sessions that last beyond 2038."
  [input]
  (byte-array
   (for [n bit-shifts]
     (bit-and 0xff (bit-shift-right input n)))))

(defn bytes->int
  "Get back a 32-bit integer from a 4-wide byte-array"
  [^bytes input]
  (reduce bit-or 0
          (map (fn [x n] (bit-shift-left (bit-and x 0xff) n))
               (seq input)
               bit-shifts)))

(defn int->b64
  "Convert an integer to an URL encoded Base64 string."
  [input]
  (b->b64 (int->bytes input)))

(defn ^Integer b64->int
  "Convert an URL encoded Base64 string to an integer."
  [input]
  (bytes->int (b64->b input)))
