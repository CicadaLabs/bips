(ns bips.bip39-test
  (:require
    [bips.bip39 :refer [check-mnemonic
                        entropy->mnemonic
                        mnemonic->seed]]
    [bips.utils :refer [random-entropy entropy-string->entropy-byte-array]]
    [clojure.edn :as edn]
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

(def test-vectors-en
  (-> "./test/bips/fixtures/vectors.edn"
      slurp
      edn/read-string
      :english))

(def test-vectors-jp
  (-> "./test/bips/fixtures/vectors.edn"
      slurp
      edn/read-string
      :japanese))

;; https://gist.github.com/joelittlejohn/2ecc1256e5d184d78f30fd6c4641099e
(defn add-test
  "Add a test to the given namespace. The body of the test is given as
  the thunk test-fn. Useful for adding dynamically generated deftests."
  [name ns test-fn & [metadata]]
  (intern ns (with-meta (symbol name) (merge metadata {:test #(test-fn)})) (fn [])))

(defmacro gen-test-vector [n tv]
  `(deftest n
     (let [entropy# (:entropy ~tv)
           mnemonic# (:mnemonic ~tv)
           seed# (:seed ~tv)
           passphrase# (:passphrase ~tv)]
       (is (= mnemonic#
              (entropy->mnemonic
                (entropy-string->entropy-byte-array entropy#))))
       (is (= seed#
              (mnemonic->seed mnemonic# passphrase#)))
       (is (check-mnemonic mnemonic#)))))

(defmacro gen-test-vector-jp [n tv]
  `(deftest n
     (let [entropy# (:entropy ~tv)
           mnemonic# (java.text.Normalizer/normalize (:mnemonic ~tv)
                                                     java.text.Normalizer$Form/NFKD)
           seed# (:seed ~tv)
           passphrase# (:passphrase ~tv)]
       (is (= mnemonic#
              (entropy->mnemonic
                (entropy-string->entropy-byte-array entropy#) "japanese")))
       (is (= seed#
              (mnemonic->seed mnemonic# passphrase#)))
       (is (check-mnemonic mnemonic#)))))

(doseq [i (range 0 (count test-vectors-en))]
  (let [tv (nth test-vectors-en i)]
    (add-test (symbol (str "test-vector-" i))
              (symbol (str *ns*))
              (gen-test-vector (symbol (str "test-vector-" i)) tv))))

(doseq [i (range 0 (count test-vectors-jp))]
  (let [tv (nth test-vectors-jp i)]
    (add-test (symbol (str "test-vector-jp-" i))
              (symbol (str *ns*))
              (gen-test-vector-jp (symbol (str "test-vector-jp-" i)) tv))))

(comment
  (clojure.test/run-all-tests))
