(ns cicadabank.proposals.bip39-test
  (:require
    [cicadabank.proposals.bip39 :refer [check-mnemonic
                                        entropy->mnemonic
                                        mnemonic->seed]]
    [cicadabank.proposals.utils :refer [random-entropy entropy-string->entropy-byte-array]]
    [clojure.data.json :as json]
    [clojure.test :refer [deftest is]]))

(deftest can-detect-invalid-mnemonic
  (is (thrown-with-msg? Exception #"Language not detected."
        (check-mnemonic "this is an invalid seed")))
  (is (thrown-with-msg? Exception #"Language ambigous between .*"
        (check-mnemonic "abandon")))
  (is (not (check-mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon test")))
  (is (not (check-mnemonic "useful glare domain draw begin outer record fix essence immense want defy")))
  (is (not (check-mnemonic "purpose seven minute hurry supply enlist snow guide much addict dial journey start build debate")))
  (is (not (check-mnemonic "brain model pact ostrich hospital uphold track glass blossom clerk popular crunch run drive visit bus mean syrup")))
  (is (not (check-mnemonic "share fury series transfer siren crush weasel blossom game glare author river dirt north mention glance split puzzle doll home coyote")))
  (is (not (check-mnemonic "clip blame assume hold label rocket supply buzz diary short flag flavor maze live cross hour renew filter ankle scissors secret trumpet planet fatal")))
  (is (not (check-mnemonic "depart alpha dial coach small patch fee grass brief boat quality label oyster much drop stock oxygen catalog sting choice response black gasp later draw"))))

(deftest can-detect-valid-mnemonic
  (is (check-mnemonic "crop cash unable insane eight faith inflict route frame loud box vibrant"))
  (is (check-mnemonic "giggle load civil velvet legend drink letter symbol vivid tube parent plug accuse fault choose ahead bomb make novel potato enrich honey cable exchange")))

(deftest thows-exception-on-invalid-entropy
  (is (thrown-with-msg? Exception #"Invalid entropy."
        (entropy->mnemonic (random-entropy 120)))))

(deftest can-generate-seed-phrase-from-an-entropy
  (is (= "crop cash unable insane eight faith inflict route frame loud box vibrant"
         (entropy->mnemonic [0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84, 0x6A, 0x79,]))))

;; https://github.com/trezor/python-mnemonic/blob/master/vectors.json
(def test-vectors
  (-> "resources/assets/bip-39/vectors.json"
      slurp
      json/read-str
      (get "english")))

;; https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
(def test-vectors-jp
  (-> "resources/assets/bip-39/test_JP_BIP39.json"
      slurp
      json/read-str))

;; https://gist.github.com/joelittlejohn/2ecc1256e5d184d78f30fd6c4641099e
(defn add-test
  "Add a test to the given namespace. The body of the test is given as
  the thunk test-fn. Useful for adding dynamically generated deftests."
  [name ns test-fn & [metadata]]
  (intern ns (with-meta (symbol name) (merge metadata {:test #(test-fn)})) (fn [])))

(defmacro gen-test-vector [n tv]
  `(deftest n
     (let [entropy# (first ~tv)
           mnemonic# (second ~tv)
           seed# (nth ~tv 2)]
       (is (= mnemonic#
              (entropy->mnemonic
                (entropy-string->entropy-byte-array entropy#))))
       (is (= seed#
              (mnemonic->seed mnemonic# "TREZOR")))
       (is (check-mnemonic mnemonic#)))))

(defmacro gen-test-vector-jp [n tv]
  `(deftest n
     (let [entropy# (get ~tv "entropy")
           mnemonic# (java.text.Normalizer/normalize (get ~tv "mnemonic")
                                                     java.text.Normalizer$Form/NFKD)
           seed# (get ~tv "seed")
           passphrase# (get ~tv "passphrase")]
       (is (= mnemonic#
              (entropy->mnemonic
                (entropy-string->entropy-byte-array entropy#) "japanese")))
       (is (= seed#
              (mnemonic->seed mnemonic# passphrase#)))
       (is (check-mnemonic mnemonic#)))))

(doseq [tv test-vectors
        i (range 1 (count test-vectors))]
  (add-test (symbol (str "test-vector-" i))
            (symbol (str *ns*))
            (gen-test-vector (symbol (str "test-vector-" i)) tv)))

(doseq [tv test-vectors-jp
        i (range 1 (count test-vectors-jp))]
  (add-test (symbol (str "test-vector-jp-" i))
            (symbol (str *ns*))
            (gen-test-vector-jp (symbol (str "test-vector-jp-" i)) tv)))

(comment
  (clojure.test/run-all-tests))