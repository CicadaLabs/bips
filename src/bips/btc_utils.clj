(ns bips.btc-utils
  (:require
    [alphabase.base58 :as base58]
    [clj-commons.digest :as digest])
  (:import
    org.apache.commons.codec.binary.Hex))

(defn hex->bytes
  "Convert hexadecimal encoded string to bytes array."
  [^String data]
  (Hex/decodeHex (.toCharArray data)))

(defn privatekey->wif
  "Convert an hexadecimal encoded private key to WIF"
  [private-key network & compressed]
  (let [prefix (if (= :mainnet network)
                 "80"
                 "EF")
        suffix (if (first compressed)
                 "01"
                 "")]
    (base58/encode (hex->bytes (str (-> private-key
                                        (#(str prefix % suffix)))
                                    (-> private-key
                                        (#(str prefix % suffix))
                                        (hex->bytes)
                                        (digest/sha-256)
                                        (hex->bytes)
                                        (digest/sha-256)
                                        (#(take 8 %))
                                        (#(reduce str %))))))))
