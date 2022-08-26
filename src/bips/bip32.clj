(ns bips.bip32
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]
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
  (if (>= i (math/expt 2 31))
    (mac/hash (codecs/hex->bytes (str "00"
                                      k-par
                                      (format "%08x" i)))
              {:key (codecs/hex->bytes c-par)
               :alg :hmac+sha512})
    (let [K-par (codecs/hex->bytes
                  (.toString (Sign/publicKeyFromPrivate
                               (BigInteger. (apply str k-par)
                                            16))
                             16))
          K-par-compressed (str (if (= 0 (mod (nth K-par 63) 2))
                                  "02"
                                  "03")
                                (apply str (take 64 (codecs/bytes->hex K-par))))]
      (mac/hash (codecs/hex->bytes (str K-par-compressed
                                        (format "%08x" i)))
                {:key (codecs/hex->bytes c-par)
                 :alg :hmac+sha512}))))
