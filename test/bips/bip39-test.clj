(ns cicadabank.proposals.bip39-test
  (:require
    [clojure.test :refer [deftest is]]))

(deftest can-generate-seed-phrase
  (is (= "Wallet has been generated successfully."
         (:info (cicadabank.monero.wallet/create-wallet-from-bip39-seed
                  (java.util.UUID/randomUUID)
                  (cicadabank.proposals.bip39/generate-seed-phrase 128)
                  "")))))
