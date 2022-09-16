(ns bips.bip32
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]
    [bips.bip32-utils :refer [compress-public-key
                              decompressKey]]
    [clojure.math.numeric-tower :as math])
  (:import
    java.math.BigInteger
    org.web3j.crypto.Sign))

(defn derive-master-node
  [seed]
  (let [master-code
        (codecs/bytes->hex
          (mac/hash (codecs/hex->bytes seed) {:key (codecs/str->bytes "Bitcoin seed")
                                              :alg :hmac+sha512}))
        private-key (apply str (take 64 master-code))]
    {:private-key private-key
     :public-key (codecs/hex->bytes
                   (.toString (Sign/publicKeyFromPrivate
                                (BigInteger. (apply str private-key)
                                             16))
                              16))
     :chain-code (apply str (take-last 64 master-code))
     :depth 0}))

(defn CKDpriv [{k-par :private-key
                c-par :chain-code
                i :index
                depth :depth}]
  (let [K-par (codecs/hex->bytes
                (.toString (Sign/publicKeyFromPrivate
                             (BigInteger. (apply str k-par)
                                          16))
                           16))
        K-par-compressed (compress-public-key K-par)
        I (if (>= i (math/expt 2 31))
            (mac/hash (codecs/hex->bytes (str "00"
                                              k-par
                                              (format "%08x" i)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512})
            (mac/hash (codecs/hex->bytes (str K-par-compressed
                                              (format "%08x" i)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512}))]
    {:private-key (.toString (.mod (.add (BigInteger. k-par 16)
                                         (BigInteger. 1 (byte-array (take 32 I))))
                                   (.getN Sign/CURVE_PARAMS))
                             16)
     :chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
     :index i
     :depth depth}))

(defn CKDpub [{K-par :public-key
               c-par :chain-code
               i :index
               depth :depth}]
  (if (>= i (math/expt 2 31))
    nil
    (let [c-K-par (compress-public-key (byte-array K-par))
          I (mac/hash (codecs/hex->bytes (str c-K-par
                                              (format "%08x" i)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512})
          public-key (.getEncoded
                       (.add
                         (Sign/publicPointFromPrivate
                           (BigInteger. 1 (byte-array (take 32 I))))
                         (decompressKey (BigInteger. (apply str c-K-par) 16)
                                        (= 0 (mod (nth K-par 63) 2))))
                       false)]
      {:public-key (byte-array (take-last 64 public-key))
       :chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
       :index i
       :depth depth})))

(defn N [{k-par :private-key
          c-par :chain-code
          i :index
          depth :depth}]
  {:public-key (codecs/hex->bytes
                 (.toString
                   (Sign/publicKeyFromPrivate
                     (BigInteger. (apply str k-par) 16)) 16))
   :chain-code c-par
   :index i
   :depth depth})
