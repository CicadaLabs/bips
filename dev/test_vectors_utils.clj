(ns test-vectors-utils
  (:require
   [clojure.test :as t]
   [clojure.data.json :as json]
   [clojure.edn :as edn]))

(def test-vectors (atom {:english []
                         :japanese []}))

;; https://github.com/trezor/python-mnemonic/blob/master/vectors.json
(def test-vectors-en
  (-> "resources/assets/bip-39/vectors.json"
      slurp
      json/read-str
      (get "english")))

;; https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
(def test-vectors-jp
  (-> "resources/assets/bip-39/test_JP_BIP39.json"
      slurp
      json/read-str))

(doseq [tv test-vectors-en]
  (swap! test-vectors update-in [:english] conj {:entropy (first tv)
                                                 :mnemonic (second tv)
                                                 :passphrase "TREZOR"
                                                 :seed (nth tv 2)
                                                 :bip32-xprv (nth tv 3)}))

(doseq [tv test-vectors-jp]
  (swap! test-vectors update-in [:japanese] conj {:entropy (get tv "entropy")
                                                  :mnemonic (get tv "mnemonic")
                                                  :passphrase (get tv "passphrase")
                                                  :seed (get tv "seed")
                                                  :bip32-xprv (get tv "bip32_xprv")}))

(comment
  (spit "test/cicadabank/proposals/vectors.edn" (prn-str @test-vectors))
  (first (get (edn/read-string (slurp "test/cicadabank/proposals/vectors.edn")) :english)))
