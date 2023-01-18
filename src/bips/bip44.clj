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

(ns bips.bip44
  (:require
    [bips.constants :as const]))

(defn derivation-path
  "The derivation-path multi-arity function. The first version takes
  four arguments: a `coin-type`, an `account` index, a `chain` type,
  and an `address` index.  It uses these values to construct a string
  representing a path to a specific wallet address.  Throws an
  exception with an error message if the `coin-type` in not found in
  `coin_types.edn`.  A second version taking two arguments is used to
  derive an account address from a `coin-type` and an `account`
  index."
  ([coin-type account chain address]
   (str (derivation-path coin-type account) "/" (get const/chain-map chain) "/" address))
  ([coin-type account]
   (if-let [matching-coin-type (first (filter #(= (:symbol %) coin-type)
                                              const/coin-types))]
     (str "m/44'/" (:coin-type matching-coin-type)
          "'/" account "'")
     (throw (Exception. (str "Coin type " coin-type " not found in coin_types.edn file."))))))

(comment
  (derivation-path "BTC" 0 :external 0)
  (derivation-path "XMR" 0 :change 0))
