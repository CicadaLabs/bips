(ns bips.constants
  (:require
    [clojure.edn :as edn]))

(defonce purpose 44)

(defonce coin_types (edn/read-string (slurp "resources/coin_types.edn")))

(defonce chain {:external 0
                :change 1})
