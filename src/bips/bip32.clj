(ns bips.bip32
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]))

(defn derive-master-code
  [seed]
  (codecs/bytes->hex
    (mac/hash (codecs/hex->bytes seed) {:key (codecs/str->bytes "Bitcoin seed")
                                        :alg :hmac+sha512})))
