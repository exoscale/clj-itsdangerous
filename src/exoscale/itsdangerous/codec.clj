(ns exoscale.itsdangerous.codec
  "Standard format coercers"
  (:require [clojure.string :as str])
  (:import java.util.Arrays
           java.util.Base64
           java.nio.ByteBuffer))

(defn ^String b->b64
  "Convert a byte array to URL encoded Base64. Padding ('=' chars) is stripped."
  [^bytes b]
  (-> (String. (.encode (Base64/getUrlEncoder) b) "UTF-8")
      (str/replace #"=+$" "")))

(defn ^String s->b64
  "Convert a string to URL encoded Base64."
  [^String s]
  (b->b64 (.getBytes s "UTF-8")))

(defn b64->b
  "Decodes an URL encoded string to a byte array."
  [^String s]
  (.decode (Base64/getUrlDecoder) (.getBytes s "UTF-8")))

(defn ^String b64->s
  "Decodes an URL encoded string to a string."
  [^String s]
  (String. ^bytes (b64->b s) "UTF-8"))

(defn int->bytes
  "Convert an integer to a variable-length big-endian byte array.
   Leading zeros are stripped (matching Python's int_to_bytes)."
  [input]
  (let [buf (ByteBuffer/allocate 8)]
    (.putLong buf (long input))
    (.flip buf)
    (let [arr (byte-array 8)]
      (.get buf arr)
      (if (every? zero? arr)
        (byte-array 0)
        (let [start (loop [i 0]
                      (if (and (< i 7) (zero? (aget arr i)))
                        (recur (inc i))
                        i))]
           (Arrays/copyOfRange arr ^int start 8))))))

(defn bytes->int
  "Get back a 64-bit integer from a variable-length byte-array.
   Right-justifies to 8 bytes (matching Python's bytes_to_int)."
  [^bytes input]
  (if (zero? (count input))
    0
    (let [buf (ByteBuffer/allocate 8)]
      (.position buf (- 8 (count input)))
      (.put buf input)
      (.flip buf)
      (.getLong buf))))

(defn int->b64
  "Convert an integer to a URL encoded Base64 string."
  [input]
  (b->b64 (int->bytes input)))

(defn ^Integer b64->int
  "Convert a URL encoded Base64 string to an integer."
  [input]
  (bytes->int (b64->b input)))
