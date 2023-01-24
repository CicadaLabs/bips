;; Copyright © 2022 CicadaBank

;; Permission is hereby granted, free of charge, to any person obtaining a copy of
;; this software and associated documentation files (the "Software"), to deal in
;; the Software without restriction, including without limitation the rights to
;; use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
;; the Software, and to permit persons to whom the Software is furnished to do so,
;; subject to the following conditions:

;; The above copyright notice and this permission notice shall be included in all
;; copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
;; FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
;; COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
;; IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

(ns bips.bip32-test
  (:require
    [bips.bip32 :refer [derive-master-node
                        CKDpriv
                        CKDpub
                        N
                        derive-path]]
    [bips.bip32-utils :refer [add-point
                              CURVE_PARAMS
                              group-add
                              hardened
                              key-fingerprint
                              legacy-address
                              deserialize-base58
                              serialize
                              key-identifier
                              serialize-base58]]
    [bips.btc-utils :refer [privatekey->wif]]
    [buddy.core.codecs :as codecs]
    [buddy.core.mac]
    [clojure.edn :as edn]
    [clojure.test :refer [deftest is]]))

(def test-vectors
  (-> "test/bips/fixtures/bip32-vectors.edn"
      slurp
      edn/read-string))

;; https://gist.github.com/joelittlejohn/2ecc1256e5d184d78f30fd6c4641099e
(defn add-test
  "Add a test to the given namespace. The body of the test is given as
  the thunk test-fn. Useful for adding dynamically generated deftests."
  [name ns test-fn & [metadata]]
  (intern ns (with-meta (symbol name) (merge metadata {:test #(test-fn)})) (fn [])))

(defmacro gen-test-func
  "Generates a function based on a test vector `tv`. The test vector is a map
  that describes a seed and it's derived keys. E.g.:

  {:seed \"000102030405060708090a0b0c0d0e0f\"
  :derived-keys
  [{:path \"m\"
    :identifier \"3442193e1bb70916e914552172cd4e2dbc9df811\"
    :fingerprint \"3442193e\"
    :address \"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma\"
    :private-key \"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35\"
    :wif \"L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW\"
    :public-key \"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\"
    :chain-code \"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508\"
    :serialized-pubkey \"0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\"
    :serialized-prvkey \"0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35\"
    :bip32-xpubkey \"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8\"
    :bip32-xprvkey \"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi\"
    :parent-fingerprint \"00000000\"
    :index 0}]}"
  [tv]
  `(fn []
     (let [seed# (:seed ~tv)]
       (doseq [i# (range (count (:derived-keys ~tv)))]
         (let [derived-key# (nth (:derived-keys ~tv) i#)
               path# (:path derived-key#)
               extended-private-key# (derive-path seed# path# :private)
               extended-public-key# (derive-path seed# path# :public)
               bip32-xprvkey# (:bip32-xprvkey derived-key#)
               bip32-xpubkey# (:bip32-xpubkey derived-key#)
               identifier# (:identifier derived-key#)
               fingerprint# (:fingerprint derived-key#)
               address# (:address derived-key#)
               private-key# (:private-key derived-key#)
               wif# (:wif derived-key#)
               public-key# (:public-key derived-key#)
               chain-code# (:chain-code derived-key#)
               serialized-private-key# (:serialized-prvkey derived-key#)
               serialized-public-key# (:serialized-pubkey derived-key#)
               parent-fingerprint# (:parent-fingerprint derived-key#)
               index# (:index derived-key#)]
           (is (= bip32-xprvkey#
                  (serialize-base58 :mainnet :private (:depth extended-private-key#)
                                    (Long/parseLong parent-fingerprint# 16) index#
                                    (:chain-code extended-private-key#)
                                    (:private-key extended-private-key#))))
           (is (= bip32-xpubkey#
                  (serialize-base58 :mainnet :public (:depth extended-public-key#)
                                    (Long/parseLong parent-fingerprint# 16) index#
                                    (:chain-code extended-public-key#)
                                    (:public-key extended-public-key#))))
           (is (= identifier#
                  (codecs/bytes->hex
                    (key-identifier (:public-key extended-public-key#)))))
           (is (= (Long/parseLong fingerprint# 16)
                  (key-fingerprint (:public-key extended-public-key#))))
           (is (= address#
                  (legacy-address (:public-key extended-public-key#) :mainnet)))
           (is (= private-key#
                  (:private-key extended-private-key#)))
           (is (= wif#
                  (privatekey->wif (:private-key extended-private-key#)
                                   :mainnet true)))
           (is (= public-key#
                  (:public-key extended-public-key#)))
           (is (= chain-code#
                  (:chain-code extended-public-key#)))
           (is (= serialized-private-key#
                  (serialize :mainnet :private (:depth extended-private-key#)
                             (Long/parseLong parent-fingerprint# 16) index#
                             (:chain-code extended-private-key#)
                             (:private-key extended-private-key#))))
           (is (= serialized-public-key#
                  (serialize :mainnet :public (:depth extended-public-key#)
                             (Long/parseLong parent-fingerprint# 16) index#
                             (:chain-code extended-public-key#)
                             (:public-key extended-public-key#)))))))))

(doseq [i (range (count test-vectors))]
  (add-test (symbol (format "test-vector-%d-generated" i))
            (symbol (str *ns*))
            (gen-test-func (nth test-vectors i))))

;; The CKD functions sometimes return 31 byte keys, the buffer has to be padded to 32 bytes
(deftest test-vector-3
  (let [seed "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        ;; Chain m
        master-private-key (derive-path seed "m" :private)
        base58-encoded-master-private-key (serialize-base58 :mainnet :private (:depth master-private-key)
                                                            0 0
                                                            (:chain-code master-private-key)
                                                            (:private-key master-private-key))
        master-public-key (derive-path seed "m" :public)
        base58-encoded-master-public-key (serialize-base58 :mainnet :public (:depth master-public-key)
                                                           0 0
                                                           (:chain-code master-public-key)
                                                           (:public-key master-public-key))
        master-node (derive-master-node seed)
        base58-encoded-master-node-private-key (serialize-base58 :mainnet :private (:depth master-node)
                                                                 0 0
                                                                 (:chain-code master-node)
                                                                 (:private-key master-node))
        base58-encoded-master-node-public-key (serialize-base58 :mainnet :public (:depth master-node)
                                                                0 0
                                                                (:chain-code master-node)
                                                                (:public-key master-node))
        master-fingerprint (key-fingerprint (:public-key master-public-key))
        ;; Chain m/0H
        child-private-key (derive-path seed "m/0H" :private)
        base58-encoded-child-private-key (serialize-base58 :mainnet :private (:depth child-private-key)
                                                           master-fingerprint (:index child-private-key)
                                                           (:chain-code child-private-key)
                                                           (:private-key child-private-key))
        child-public-key (derive-path seed "m/0H" :public)
        base58-encoded-child-public-key (serialize-base58 :mainnet :public (:depth child-public-key)
                                                          master-fingerprint (:index child-public-key)
                                                          (:chain-code child-public-key)
                                                          (:public-key child-public-key))
        child-node (CKDpriv master-node (hardened 0))
        base58-encoded-child-node-private-key (serialize-base58 :mainnet :private (:depth child-node)
                                                                master-fingerprint (:index child-node)
                                                                (:chain-code child-node)
                                                                (:private-key child-node))
        child-node-public-key (N child-node)
        base58-encoded-child-node-public-key (serialize-base58 :mainnet :public (:depth child-node-public-key)
                                                               master-fingerprint (:index child-node-public-key)
                                                               (:chain-code child-node-public-key)
                                                               (:public-key child-node-public-key))]
    ;; Chain m
    (is (= "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
           base58-encoded-master-node-private-key))
    (is (= "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
           base58-encoded-master-node-public-key))
    (is (= "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
           base58-encoded-master-private-key))
    (is (= "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
           base58-encoded-master-public-key))
    ;; Chain m/0H
    (is (= "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
           base58-encoded-child-node-private-key)
        "leading zeros are retained.")
    (is (= "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
           base58-encoded-child-node-public-key)
        "leading zeros are retained.")
    (is (= "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
           base58-encoded-child-private-key))
    (is (= "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
           base58-encoded-child-public-key)
        "leading zeros are retained.")
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub master-node (hardened 0))))))

;; The CKD functions sometimes return 31 byte keys, the buffer has to be padded to 32 bytes
(deftest test-vector-4
  (let [seed "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"
        ;; Chain m
        master-private-key (derive-path seed "m" :private)
        base58-encoded-master-private-key (serialize-base58 :mainnet :private (:depth master-private-key)
                                                            0 0
                                                            (:chain-code master-private-key)
                                                            (:private-key master-private-key))
        master-public-key (derive-path seed "m" :public)
        base58-encoded-master-public-key (serialize-base58 :mainnet :public (:depth master-public-key)
                                                           0 0
                                                           (:chain-code master-public-key)
                                                           (:public-key master-public-key))
        master-node (derive-master-node seed)
        base58-encoded-master-node-private-key (serialize-base58 :mainnet :private (:depth master-node)
                                                                 0 0
                                                                 (:chain-code master-node)
                                                                 (:private-key master-node))
        base58-encoded-master-node-public-key (serialize-base58 :mainnet :public (:depth master-node)
                                                                0 0
                                                                (:chain-code master-node)
                                                                (:public-key master-node))
        master-fingerprint (key-fingerprint (:public-key master-node))
        ;; Chain m/0H
        child-private-key (derive-path seed "m/0H" :private)
        base58-encoded-child-private-key (serialize-base58 :mainnet :private (:depth child-private-key)
                                                           master-fingerprint (:index child-private-key)
                                                           (:chain-code child-private-key)
                                                           (:private-key child-private-key))
        child-public-key (derive-path seed "m/0H" :public)
        base58-encoded-child-public-key (serialize-base58 :mainnet :public (:depth child-public-key)
                                                          master-fingerprint (:index child-public-key)
                                                          (:chain-code child-public-key)
                                                          (:public-key child-public-key))
        child-node (CKDpriv master-node (hardened 0))
        base58-encoded-child-node-private-key (serialize-base58 :mainnet :private (:depth child-node)
                                                                master-fingerprint (:index child-node)
                                                                (:chain-code child-node)
                                                                (:private-key child-node))
        child-node-public-key (N child-node)
        base58-encoded-child-node-public-key (serialize-base58 :mainnet :public (:depth child-node-public-key)
                                                               master-fingerprint (:index child-node-public-key)
                                                               (:chain-code child-node-public-key)
                                                               (:public-key child-node-public-key))
        child-fingerprint (key-fingerprint (:public-key child-node-public-key))
        ;; Chain m/0H/1H
        grandchild-private-key (derive-path seed "m/0H/1H" :private)
        base58-encoded-grandchild-private-key (serialize-base58 :mainnet :private (:depth grandchild-private-key)
                                                                child-fingerprint
                                                                (:index grandchild-private-key)
                                                                (:chain-code grandchild-private-key)
                                                                (:private-key grandchild-private-key))
        grandchild-public-key (derive-path seed "m/0H/1H" :public)
        base58-encoded-grandchild-public-key (serialize-base58 :mainnet :public (:depth grandchild-public-key)
                                                               child-fingerprint
                                                               (:index grandchild-public-key)
                                                               (:chain-code grandchild-public-key)
                                                               (:public-key grandchild-public-key))
        grandchild-node-private-key (CKDpriv child-node (hardened 1))
        base58-encoded-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth grandchild-node-private-key)
                                                                     child-fingerprint (:index grandchild-node-private-key)
                                                                     (:chain-code grandchild-node-private-key)
                                                                     (:private-key grandchild-node-private-key))
        grandchild-node-public-key (N grandchild-node-private-key)
        base58-encoded-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth grandchild-node-public-key)
                                                                    child-fingerprint (:index grandchild-node-public-key)
                                                                    (:chain-code grandchild-node-public-key)
                                                                    (:public-key grandchild-node-public-key))]
    ;; Chain m
    (is (= "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
           base58-encoded-master-private-key))
    (is (= "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
           base58-encoded-master-public-key))
    (is (= "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
           base58-encoded-master-node-private-key))
    (is (= "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
           base58-encoded-master-node-public-key))
    ;; Chain m/0H
    (is (= "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
           base58-encoded-child-node-private-key))
    (is (= "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
           base58-encoded-child-node-public-key))
    (is (= "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
           base58-encoded-child-private-key))
    (is (= "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
           base58-encoded-child-public-key))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub master-node (hardened 0))))
    ;; Chain m/0H/1H
    (is (= "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
           base58-encoded-grandchild-private-key)
        "leading zeros are retained.")
    (is (= "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
           base58-encoded-grandchild-public-key)
        "leading zeros are retained.")
    (is (= "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
           base58-encoded-grandchild-node-private-key)
        "leading zeros are retained.")
    (is (= "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
           base58-encoded-grandchild-node-public-key)
        "leading zeros are retained.")))

(deftest test-vector-5
  (is (thrown-with-msg? Exception #"pubkey version / prvkey mismatch"
        (deserialize-base58 "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm"))
      "invalid extended keys are recognized as invalid.")
  (is (thrown-with-msg? Exception #"prvkey version / pubkey mismatch"
        (deserialize-base58 "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid pubkey prefix: .*"
        (deserialize-base58 "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid prvkey prefix: .*"
        (deserialize-base58 "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid pubkey prefix: .*"
        (deserialize-base58 "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid prvkey prefix: .*"
        (deserialize-base58 "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"zero depth with non-zero parent fingerprint: .*"
        (deserialize-base58 "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"zero depth with non-zero parent fingerprint: .*"
        (deserialize-base58 "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"zero depth with non-zero index"
        (deserialize-base58 "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"zero depth with non-zero index"
        (deserialize-base58 "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"unknown extended key version: .*"
        (deserialize-base58 "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"unknown extended key version: .*"
        (deserialize-base58 "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"private key .* not in 1..n-1"
        (deserialize-base58 "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"private key .* not in 1..n-1"
        (deserialize-base58 "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid pubkey: .*"
        (deserialize-base58 "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY")
        "invalid extended keys are recognized as invalid."))
  (is (thrown-with-msg? Exception #"invalid checksum: .*"
        (deserialize-base58 "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL"))
      "invalid extended keys are recognized as invalid."))

(deftest test-deserialization-base58
  (is (thrown-with-msg? Exception #"Found unexpected data in key"
        (deserialize-base58 "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW555"))
      "exeption is thrown when there are more data than expected."))

(deftest test-reserialization-base58
  (let [;; This is the public encoding of the key with path m/0H/1/2H from BIP32 published test vector 1:
        ;; https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        encoded-1 "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        decoded-1 (deserialize-base58 encoded-1)
        ;; This encoding is the same key but including its private data:
        encoded-2 "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        decoded-2 (deserialize-base58 encoded-2)
        ;; These encodings are of the the root key of that hierarchy
        encoded-3 "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        decoded-3 (deserialize-base58 encoded-3)
        encoded-4 "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        decoded-4 (deserialize-base58 encoded-4)]
    (is (= encoded-1
           (serialize-base58 (:network decoded-1)
                             (:type decoded-1)
                             (:depth decoded-1)
                             (:fingerprint decoded-1)
                             (:index decoded-1)
                             (:chain-code decoded-1)
                             (case (:type decoded-1)
                               :public
                               (:public-key decoded-1)
                               :private
                               (:private-key decoded-1))))
        "Reserializing a deserialized key should yield the original input.")
    (is (= 3 (:depth decoded-1)))
    (is (= (Long/parseLong "bef5a2f9" 16) (:fingerprint decoded-1)))
    (is (= encoded-2
           (serialize-base58 (:network decoded-2)
                             (:type decoded-2)
                             (:depth decoded-2)
                             (:fingerprint decoded-2)
                             (:index decoded-2)
                             (:chain-code decoded-2)
                             (case (:type decoded-2)
                               :public
                               (:public-key decoded-2)
                               :private
                               (:private-key decoded-2))))
        "Reserializing a deserialized key should yield the original input.")
    (is (= 3 (:depth decoded-2)))
    (is (= (Long/parseLong "bef5a2f9" 16) (:fingerprint decoded-2)))
    (is (= 0 (:depth decoded-3))
        "depth of root node public HD key should be zero")
    (is (= 0 (:fingerprint decoded-3))
        "Parent fingerprint of root node public HD key should be zero")
    (is (= 0 (:depth decoded-4))
        "depth of root node public HD key should be zero")
    (is (= 0 (:fingerprint decoded-4))
        "Parent fingerprint of root node public HD key should be zero")))

(deftest exceptional-cases-derive-master-node
  (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                           (byte-array
                                             (codecs/hex->bytes
                                               (apply str (take 128 (repeat "0"))))))}
    #(is (thrown-with-msg? Exception
                           #"master key is invalid."
           (derive-master-node (codecs/bytes->hex
                                 (codecs/str->bytes "test"))))
         "In case parse256(IL) is 0, the master key is invalid."))
  (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                           (byte-array
                                             (concat
                                               (codecs/hex->bytes
                                                 (.toString (.getN CURVE_PARAMS) 16))
                                               (codecs/hex->bytes
                                                 (.toString (.getN CURVE_PARAMS) 16)))))}
    #(is (thrown-with-msg? Exception
                           #"master key is invalid."
           (derive-master-node (codecs/bytes->hex
                                 (codecs/str->bytes "test"))))
         "In case parse256(IL) = n, the master key is invalid."))
  (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                           (byte-array
                                             (concat
                                               (codecs/hex->bytes
                                                 (.toString
                                                   (.add (.getN CURVE_PARAMS) BigInteger/ONE) 16))
                                               (codecs/hex->bytes
                                                 (.toString (.getN CURVE_PARAMS) 16)))))}
    #(is (thrown-with-msg? Exception
                           #"master key is invalid."
           (derive-master-node (codecs/bytes->hex
                                 (codecs/str->bytes "test"))))
         "In case parse256(IL) > n, the master key is invalid.")))

(deftest exceptional-cases-CKDpriv
  (let [master-key (derive-master-node
                     (codecs/bytes->hex (codecs/str->bytes "test")))]
    (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                             (byte-array
                                               (concat
                                                 (codecs/hex->bytes
                                                   (.toString (.getN CURVE_PARAMS) 16))
                                                 (codecs/hex->bytes
                                                   (.toString (.getN CURVE_PARAMS) 16)))))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpriv master-key 1))
           "Testing exceptional cases for CKDpriv.
   In case parse256(IL) = n, the resulting key is invalid,
   and one should proceed with the next value for i."))
    (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                             (byte-array
                                               (concat
                                                 (codecs/hex->bytes
                                                   (.toString
                                                     (.add (.getN CURVE_PARAMS) BigInteger/ONE) 16))
                                                 (codecs/hex->bytes
                                                   (.toString (.getN CURVE_PARAMS) 16)))))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpriv master-key 1))
           "Testing exceptional cases for CKDpriv.
   In case parse256(IL) > n, the resulting key is invalid,
   and one should proceed with the next value for i."))
    (with-redefs-fn
      {#'group-add (fn [_ _]
                     (BigInteger/ZERO))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpriv master-key 1))
           "Testing exceptional cases for CKDpriv.
   In case ki = 0, the resulting key is invalid,
   and one should proceed with the next value for i."))))

(deftest exceptional-cases-CKDpub
  (let [master-key (derive-master-node
                     (codecs/bytes->hex (codecs/str->bytes "test")))]
    (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                             (byte-array
                                               (concat
                                                 (codecs/hex->bytes
                                                   (.toString (.getN CURVE_PARAMS) 16))
                                                 (codecs/hex->bytes
                                                   (.toString (.getN CURVE_PARAMS) 16)))))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpub master-key 1))
           "Testing exceptional cases for CKDpub.
   In case parse256(IL) = n, the resulting key is invalid,
   and one should proceed with the next value for i."))
    (with-redefs-fn {#'buddy.core.mac/hash (fn [_ _]
                                             (byte-array
                                               (concat
                                                 (codecs/hex->bytes
                                                   (.toString
                                                     (.add (.getN CURVE_PARAMS)
                                                           BigInteger/ONE) 16))
                                                 (codecs/hex->bytes
                                                   (.toString
                                                     (.getN CURVE_PARAMS) 16)))))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpub master-key 1))
           "Testing exceptional cases for CKDpub.
   In case parse256(IL) > n, the resulting key is invalid,
   and one should proceed with the next value for i."))
    (with-redefs-fn {#'add-point (fn [_ _]
                                   (.getInfinity (.getCurve CURVE_PARAMS)))}
      #(is (thrown-with-msg? Exception
                             #"key is invalid, proceed with the next value for i."
             (CKDpub master-key 1))
           "Testing exceptional cases for CKDpub.
   In case Ki is the point at infinity, the resulting key is invalid,
   and one should proceed with the next value for i."))))

;; Test from https://github.com/bitcoinj/bitcoinj/blob/master/core/src/test/java/org/bitcoinj/crypto/ChildKeyDerivationTest.java
(deftest test-serialization-main-and-test-networks
  (let [master-node (derive-master-node (codecs/bytes->hex
                                          (.getBytes "satoshi lives!")))
        base58-encoded-master-node-private-key (serialize-base58 :mainnet :private (:depth master-node)
                                                                 0 0
                                                                 (:chain-code master-node)
                                                                 (:private-key master-node))
        base58-encoded-master-node-public-key (serialize-base58 :mainnet :public (:depth master-node)
                                                                0 0
                                                                (:chain-code master-node)
                                                                (:public-key master-node))
        base58-encoded-master-node-private-key-testnet (serialize-base58 :testnet :private (:depth master-node)
                                                                         0 0
                                                                         (:chain-code master-node)
                                                                         (:private-key master-node))
        base58-encoded-master-node-public-key-testnet (serialize-base58 :testnet :public (:depth master-node)
                                                                        0 0
                                                                        (:chain-code master-node)
                                                                        (:public-key master-node))]
    (is (= "xprv9s21ZrQH143K2dhN197jMx1ppxRBHFKJpMqdLsF1ewxncv7quRED8N5nksxphju3W7naj1arF56L5PUEWfuSk8h73Sb2uh7bSwyXNrjzhAZ"
           base58-encoded-master-node-private-key))
    (is (= "xpub661MyMwAqRbcF7mq7Aejj5xZNzFfgi3ABamE9FedDHVmViSzSxYTgAQGcATDo2J821q7Y9EAagjg5EP3L7uBZk11PxZU3hikL59dexfLkz3"
           base58-encoded-master-node-public-key))
    (is (= "tprv8ZgxMBicQKsPdSvtfhyEXbdp95qPWmMK9ukkDHfU8vTGQWrvtnZxe7TEg48Ui7HMsZKMj7CcQRg8YF1ydtFPZBxha5oLa3qeN3iwpYhHPVZ"
           base58-encoded-master-node-private-key-testnet))
    (is (= "tpubD6NzVbkrYhZ4WuxgZMdpw1Hvi7MKg6YDjDMXVohmZCFfF17hXBPYpc56rCY1KXFMovN29ik37nZimQseiykRTBTJTZJmjENyv2k3R12BJ1M"
           base58-encoded-master-node-public-key-testnet))))

;; Test vector for https://github.com/CicadaBank/bips/issues/13
(deftest test-vector-6
  (let [seed "f949850abc48c908df447f2bc1e1f1a98a3e5a048571bda55ce9b56784f1dbccd12340ab013872a659f3bdfff16470bd1fbab9b05ba6ade5d52e36efea3a8e4d"
        ;; Chain: m
        master-node (derive-master-node seed)
        master-private-key (:private-key master-node)
        master-public-key (:public-key master-node)
        master-chain-code (:chain-code master-node)
        master-node-fingerprint (key-fingerprint master-public-key)
        bip32-xprv-master-private-key (serialize-base58 :mainnet :private 0 0 0
                                                        master-chain-code
                                                        master-private-key)
        bip32-xpub-master-public-key (serialize-base58 :mainnet :public 0 0 0
                                                       master-chain-code
                                                       master-public-key)
        ;; Chain: m/44H
        child-node (CKDpriv master-node (hardened 44))
        child-private-key (:private-key child-node)
        child-public-key (:public-key (N child-node))
        child-chain-code (:chain-code child-node)
        child-node-fingerprint (key-fingerprint child-public-key)
        bip32-xprv-child-private-key (serialize-base58 :mainnet :private
                                                       (:depth child-node)
                                                       master-node-fingerprint
                                                       (hardened 44)
                                                       child-chain-code
                                                       child-private-key)
        bip32-xpub-child-public-key (serialize-base58 :mainnet :public
                                                      (:depth child-node)
                                                      master-node-fingerprint
                                                      (hardened 44)
                                                      child-chain-code
                                                      child-public-key)
        ;; Chain: m/44H/0H
        grandchild-node (CKDpriv child-node (hardened 0))
        grandchild-private-key (:private-key grandchild-node)
        grandchild-public-key (:public-key (N grandchild-node))
        grandchild-chain-code (:chain-code grandchild-node)
        grandchild-node-fingerprint (key-fingerprint grandchild-public-key)
        bip32-xprv-grandchild-private-key (serialize-base58 :mainnet :private
                                                            (:depth grandchild-node)
                                                            child-node-fingerprint
                                                            (hardened 0)
                                                            grandchild-chain-code
                                                            grandchild-private-key)
        bip32-xpub-grandchild-public-key (serialize-base58 :mainnet :public
                                                           (:depth grandchild-node)
                                                           child-node-fingerprint
                                                           (hardened 0)
                                                           grandchild-chain-code
                                                           grandchild-public-key)
        ;; Chain: m/44H/0H/0H
        grand-grandchild-node (CKDpriv grandchild-node (hardened 0))
        grand-grandchild-private-key (:private-key grand-grandchild-node)
        grand-grandchild-public-key (:public-key (N grand-grandchild-node))
        grand-grandchild-chain-code (:chain-code grand-grandchild-node)
        bip32-xprv-grand-grandchild-private-key (serialize-base58 :mainnet :private
                                                                  (:depth grand-grandchild-node)
                                                                  grandchild-node-fingerprint
                                                                  (hardened 0)
                                                                  grand-grandchild-chain-code
                                                                  grand-grandchild-private-key)
        bip32-xpub-grand-grandchild-public-key (serialize-base58 :mainnet :public
                                                                 (:depth grand-grandchild-node)
                                                                 grandchild-node-fingerprint
                                                                 (hardened 0)
                                                                 grand-grandchild-chain-code
                                                                 grand-grandchild-public-key)]
    ;; Chain: m
    (is (= "xprv9s21ZrQH143K39jyBqhmMnfUmrdCawvW71C5VEmCZhNKn9BKnpatEbMTUyvbSvmPReDfVuZ6zAfeuD7M6TzJiPFCgQEkHax4FFSCnVWRVJY"
           bip32-xprv-master-private-key))
    (is (= "xpub661MyMwAqRbcFdpSHsEmivcDKtTgzQeMUE7gHdAp82uJewWULMu8nPfwLFUJEY5Aag3VFP2La4n33RbRtVjnwcVkdQRafL8sxb7zKcxdURZ"
           bip32-xpub-master-public-key))
    (is (= "1d47cce7" (format "%x" master-node-fingerprint)))
    ;; Chain: m/44H
    (is (= "xprv9u7dR1X51to2TTxC41mr1TyT9FfpLJMUjDrzHL5kbkbqHXb7ncnCiD2j1snKogc3Wf4XBkd2oFdCZzjqjDhcxVt9sRVaMWFDuYTWfEKQVBz"
           bip32-xprv-child-private-key))
    (is (= "xpub686ypX3xrGMKfx2fA3JrNbvBhHWJjm5L6Snb5iVNA68pAKvGLA6TG1MCs87Y3yCEhiukunYMaKNKEowKLGMM685df7jTao6mtXFcYtZzCsJ"
           bip32-xpub-child-public-key))
    (is (= "c2f6d81" (format "%x" child-node-fingerprint)))
    ;; Chain: m/44H/0H
    (is (= "xprv9vsUaQydQJbS21eDwfKv3WYoU9cr1JcFxt252mQneUB4ABBQScW5sx7ZjJ5HMGDGy1coR5Cvit6YWio3Nj4fSiBAfJFJMMWHNdBB3FEowpt"
           bip32-xprv-grandchild-private-key))
    (is (= "xpub69rpyvWXEg9jEVih3grvQeVY2BTLQmL7L6wfq9pQCoi32yWYz9pLRkS3aYXrkHLgUia7Fx9XkNJmYtdJM2HYPvXftMeL6KKaRCaemYiBBfZ"
           bip32-xpub-grandchild-public-key))
    (is (= "6ebca719" (format "%x" grandchild-node-fingerprint)))
    ;; Chain: m/44H/0H/0H
    (is (= "xprv9yUdDyYgknA92Cb4xfsqSXxQzGtELBm1kvXVvmp5MpW3UwjevPGEX29pjR9MAL13UTE1ZDfCwZ7Y3Uwpqv5BGP4cvdkS6DSTbvdYK7RicHk"
           bip32-xprv-grand-grandchild-private-key))
    (is (= "xpub6CTydV5ab9iSEgfY4hQqofu9YJiijeUs89T6jADgvA32Mk4oTvaV4pUJahHAGizYy2s3HyBRX1uiN2d94RsMawEgTMmRuDHLUR71EayS34i"
           bip32-xpub-grand-grandchild-public-key))))

(deftest threading-macro-works-with-derive-path
  (is (= (let [key "000102030405060708090a0b0c0d0e0f"
               path "m/0H/1/2H/2/1000000000"
               key-type :private]
           (-> key
               (derive-path path key-type)))
         (derive-path "000102030405060708090a0b0c0d0e0f" "m/0H/1/2H/2/1000000000" :private))))

(comment
  (clojure.test/run-all-tests))
