(ns cicadabank.proposals.bip39-test
  (:require
    [cicadabank.monero.wallet :refer [create-wallet-from-bip39-seed]]
    [cicadabank.proposals.bip39 :refer [random-binary->seed-phrase]]
    [cicadabank.proposals.utils :refer [entropy->binary random-bits entropy-string->entropy-byte-array]]
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

(deftest test-vector-1
  (is (= "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "00000000000000000000000000000000"))))))

(deftest test-vector-2
  (is (= "legal winner thank year wave sausage worth useful legal winner thank yellow"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"))))))

(deftest test-vector-3
  (is (= "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "80808080808080808080808080808080"))))))

(deftest test-vector-4
  (is (= "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "ffffffffffffffffffffffffffffffff"))))))

(deftest test-vector-5
  (is (= "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "000000000000000000000000000000000000000000000000"))))))

(deftest test-vector-6
  (is (= "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"))))))

(deftest test-vector-7
  (is (= "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "808080808080808080808080808080808080808080808080"))))))

(deftest test-vector-8
  (is (= "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "ffffffffffffffffffffffffffffffffffffffffffffffff"))))))

(deftest test-vector-9
  (is (= "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "0000000000000000000000000000000000000000000000000000000000000000"))))))

(deftest test-vector-10
  (is (= "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"))))))

(deftest test-vector-11
  (is (= "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "8080808080808080808080808080808080808080808080808080808080808080"))))))

(deftest test-vector-12
  (is (= "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))))))

(deftest test-vector-13
  (is (= "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "9e885d952ad362caeb4efe34a8e91bd2"))))))

(deftest test-vector-14
  (is (= "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"))))))

(deftest test-vector-15
  (is (= "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"))))))

(deftest test-vector-16
  (is (= "scheme spot photo card baby mountain device kick cradle pact join borrow"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "c0ba5a8e914111210f2bd131f3d5e08d"))))))

(deftest test-vector-17
  (is (= "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3"))))))

(deftest test-vector-18
  (is (= "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"))))))

(deftest test-vector-19
  (is (= "cat swing flag economy stadium alone churn speed unique patch report train"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "23db8160a31d3e0dca3688ed941adbf3"))))))

(deftest test-vector-20
  (is (= "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0"))))))

(deftest test-vector-21
  (is (= "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad"))))))

(deftest test-vector-22
  (is (= "vessel ladder alter error federal sibling chat ability sun glass valve picture"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "f30f8c1da665478f49b001d94c5fc452"))))))

(deftest test-vector-23
  (is (= "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"))))))

(deftest test-vector-24
  (is (= "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
         (random-binary->seed-phrase
           (entropy->binary
             (entropy-string->entropy-byte-array "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"))))))
