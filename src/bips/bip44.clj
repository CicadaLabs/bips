(ns bips.bip44
  (:require
    [bips.constants :as const]))

(defn derivation-path [coin_type account chain address]
  (str "m/" const/purpose "'/" (:coin_type (first (filter #(= (:symbol %) coin_type)
                                                          const/coin_types)))
       "'/" account "'/" (get const/chain chain) "/" address))

(comment
  (derivation-path "BTC" 0 :external 0)
  (derivation-path "XMR" 0 :change 0))
