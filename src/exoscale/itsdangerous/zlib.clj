(ns exoscale.itsdangerous.zlib
  "Zlib compression utilities compatible with Python's zlib.compress/decompress."
  (:import [java.io ByteArrayOutputStream]
           [java.util.zip Deflater Inflater]))

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
  "Decompress zlib-compressed data (compatible with Python's zlib.decompress)."
  [^bytes data]
  (let [inflater (Inflater.)
        baos     (ByteArrayOutputStream.)
        buffer   (byte-array 4096)]
    (.setInput inflater data)
    (loop []
      (let [n (.inflate inflater buffer)]
        (when (> n 0)
          (.write baos buffer 0 n)
          (recur))))
    (.end inflater)
    (.toByteArray baos)))

(defn compress-if-beneficial
  "Compress data with zlib if it reduces size.  Returns [compressed? data]."
  [^bytes data]
  (let [compressed (compress data)]
    (if (< (count compressed) (dec (count data)))
      [true compressed]
      [false data])))
