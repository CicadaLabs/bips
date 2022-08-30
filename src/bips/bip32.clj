(ns bips.bip32
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]
    [bips.bip32-utils :refer [compress-public-key]]
    [clojure.math.numeric-tower :as math])
  (:import
    java.math.BigInteger
    org.web3j.crypto.Sign))

(defn derive-master-code
  [seed]
  (codecs/bytes->hex
    (mac/hash (codecs/hex->bytes seed) {:key (codecs/str->bytes "Bitcoin seed")
                                        :alg :hmac+sha512})))

(defn CKDpriv [k-par c-par i]
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
     :index i}))

(defn CKDpub [K-par c-par i]
  (if (>= i (math/expt 2 31))
    nil
    (let [I (mac/hash (codecs/hex->bytes (str (codecs/bytes->hex
                                                (.getEncoded K-par true))
                                              (format "%08x" i)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512})]
      {:public-key (.getEncoded (.add
                                  (Sign/publicPointFromPrivate (BigInteger. 1 (byte-array (take 32 I))))
                                  K-par)
                                false)
       :chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
       :index i})))

(defn N [k-par c-par i]
  {:public-key (codecs/hex->bytes
                 (.toString
                   (Sign/publicKeyFromPrivate
                     (BigInteger. (apply str k-par) 16)) 16))
   :chain-code c-par
   :index i})
