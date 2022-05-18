(ns cicadabank.proposals.bip39-test
  (:require
    [cicadabank.monero.wallet :refer [create-wallet-from-bip39-seed]]
    [cicadabank.proposals.bip39 :refer [random-binary->seed-phrase]]
    [cicadabank.proposals.utils :refer [entropy->binary random-bits]]
    [clojure.test :refer [deftest is]]))

(deftest can-generate-seed-phrase-128
  (is (= "Wallet has been generated successfully."
         (:info (create-wallet-from-bip39-seed
                  (java.util.UUID/randomUUID)
                  (random-binary->seed-phrase (random-bits 128))
                  "")))))

(deftest can-generate-seed-phrase-160
  (is (= "Wallet has been generated successfully."
         (:info (create-wallet-from-bip39-seed
                  (java.util.UUID/randomUUID)
                  (random-binary->seed-phrase (random-bits  160))
                  "")))))

(deftest can-generate-seed-phrase-192
  (is (= "Wallet has been generated successfully."
         (:info (create-wallet-from-bip39-seed
                  (java.util.UUID/randomUUID)
                  (random-binary->seed-phrase (random-bits 192))
                  "")))))

(deftest can-generate-seed-phrase-256
  (is (= "Wallet has been generated successfully."
         (:info (create-wallet-from-bip39-seed
                  (java.util.UUID/randomUUID)
                  (random-binary->seed-phrase (random-bits 256))
                  "")))))

(deftest thows-exception-on-invalid-entropy
  (is (thrown-with-msg? Exception #"Invalid entropy."
        (random-binary->seed-phrase (random-bits 127)))))

(deftest can-generate-seed-phrase-from-an-entropy
  (is (= "crop cash unable insane eight faith inflict route frame loud box vibrant"
         (random-binary->seed-phrase (entropy->binary [0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84, 0x6A, 0x79,])))))
