(ns bips.constants
  (:require
    [clojure.edn :as edn]))

;; coin_types value, which is read from a file at runtime, is used to
;; find the coin type with a matching symbol to a `coin-type`.
(defonce coin-types (edn/read-string (slurp "resources/coin_types.edn")))

;; the `:external` and `:change` values representing two possible chain
;; types.
(defonce chain-map {:external 0
                    :change 1})
