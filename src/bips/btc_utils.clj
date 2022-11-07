(ns bips.btc-utils
  (:require
    [alphabase.base58 :as base58]
    [buddy.core.codecs :as codecs]
    [clj-commons.digest :as digest])
  (:import
    org.apache.commons.codec.binary.Hex))

(defn privatekey->wif
  "Convert an hexadecimal encoded private key to WIF"
  [private-key network & compressed]
  (let [prefix (if (= :mainnet network)
                 "80"
                 "EF")
        suffix (if (first compressed)
                 "01"
                 "")]
    (base58/encode (codecs/hex->bytes (str (-> private-key
                                               (#(str prefix % suffix)))
                                           (-> private-key
                                               (#(str prefix % suffix))
                                               (codecs/hex->bytes)
                                               (digest/sha-256)
                                               (codecs/hex->bytes)
                                               (digest/sha-256)
                                               (#(take 8 %))
                                               (#(reduce str %))))))))
