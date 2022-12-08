(ns bips.bip44
  (:require
    [bips.constants :as const]))

(defn derivation-path
  "The derivation-path function takes four arguments: a `coin-type`, an
  `account`, a `chain`, and an `address`.  It uses these values to
  construct a string representing a path to a specific wallet address.
  Throws an exception with an error message if the `coin-type` in not
  found in `coin_types.edn`."
  [coin-type account chain address]
  (if-let [matching-coin-type (first (filter #(= (:symbol %) coin-type)
                                             const/coin-types))]
    (str "m/44'/" (:coin-type matching-coin-type)
         "'/" account "'/" (get const/chain-map chain) "/" address)
    (throw (Exception. (str "Coin type " coin-type " not found in coin_types.edn file.")))))

(comment
  (derivation-path "BTC" 0 :external 0)
  (derivation-path "XMR" 0 :change 0))
