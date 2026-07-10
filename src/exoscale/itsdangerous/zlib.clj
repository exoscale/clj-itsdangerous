(ns exoscale.itsdangerous.zlib
  "Zlib compression utilities compatible with Python's zlib.compress/decompress."
  (:require [exoscale.ex :as ex])
  (:import [java.io ByteArrayOutputStream]
           [java.util.zip Deflater Inflater DataFormatException]))

(defn- compress
  "Compress data using zlib format (compatible with Python's zlib.compress)."
  [^bytes data]
  (let [deflater (Deflater.)
        baos     (ByteArrayOutputStream.)
        buffer   (byte-array 4096)]
    (.setInput deflater data)
    (.finish deflater)
    (loop []
      (let [n (.deflate deflater buffer)]
        (when (> n 0)
          (.write baos buffer 0 n)
          (recur))))
    (.end deflater)
    (.toByteArray baos)))

(defn decompress
  "Decompress zlib-compressed data (compatible with Python's zlib.decompress).
   Throws ::ex/forbidden if the decompressed output exceeds `max-size` bytes."
  [^bytes data ^long max-size]
  (let [inflater (Inflater.)
        baos     (ByteArrayOutputStream.)
        buffer   (byte-array 4096)]
    (.setInput inflater data)
    (loop [total 0]
      (let [n (.inflate inflater buffer)]
        (when (> n 0)
          (let [new-total (+ total n)]
            (when (> new-total max-size)
              (ex/ex-forbidden! "decompressed data exceeds maximum allowed size"
                                {:max-size max-size}))
            (.write baos buffer 0 n)
            (recur new-total)))))
    (.end inflater)
    (.toByteArray baos)))

(defn compress-if-beneficial
  "Compress data with zlib if it reduces size.  Returns [compressed? data]."
  [^bytes data]
  (let [compressed (compress data)]
    (if (< (count compressed) (dec (count data)))
      [true compressed]
      [false data])))
