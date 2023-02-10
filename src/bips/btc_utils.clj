;; Copyright © 2022 CicadaBank

;; Permission is hereby granted, free of charge, to any person obtaining a copy of
;; this software and associated documentation files (the "Software"), to deal in
;; the Software without restriction, including without limitation the rights to
;; use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
;; the Software, and to permit persons to whom the Software is furnished to do so,
;; subject to the following conditions:

;; The above copyright notice and this permission notice shall be included in all
;; copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
;; FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
;; COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
;; IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

(ns bips.btc-utils
  (:require
    [alphabase.base58 :as base58]
    [bips.bip32 :as bip32]
    [bips.bip39 :as bip39]
    [buddy.core.codecs :as codecs]
    [clj-commons.digest :as digest])
  (:import
    org.apache.commons.codec.binary.Hex))

(defn derive-from-mnemonic
  "Derive from a BIP039 mnemonic seed to a spend key for Monero."
  ([mnemonic path key-type & [password]]
   (-> (bip39/mnemonic->seed mnemonic password)
       (bip32/derive-path path key-type)
       (:private-key)))

  ([{:keys [mnemonic path key-type password]}]
   (derive-from-mnemonic mnemonic path key-type password)))

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
