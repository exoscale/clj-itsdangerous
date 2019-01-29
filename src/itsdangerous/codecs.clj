(ns itsdangerous.codecs
  (:import java.nio.ByteBuffer))

(defn int->bytes
  [^Integer input]
  (.array (doto (ByteBuffer/allocate (/ Integer/SIZE 8))
                (.putInt input))))

(defn bytes->int
  [^bytes input]
  (.getInt (doto (ByteBuffer/allocate (/ Integer/SIZE 8))
    (.put input)
    (.flip))))
