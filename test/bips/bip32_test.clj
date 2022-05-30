(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [bips.bip32 :refer [derive-master-code]]
    [clojure.test :refer [deftest is]])
  (:import
    java.math.BigInteger
    org.bitcoinj.core.Base58
    org.web3j.crypto.Sign))

(deftest derive-master-code-test
  (let [seed "000102030405060708090a0b0c0d0e0f"
        master-code (derive-master-code seed)
        master-secret-key (apply str (take 64 master-code))
        master-chain-code (apply str (take-last 64 master-code))
        private-key (str "0488ADE4"
                         "00"
                         "00000000"
                         "00000000"
                         master-chain-code
                         (str "00" (apply str master-secret-key)))
        private-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                           (byte-array (codecs/hex->bytes private-key)))))
        master-public-key (codecs/hex->bytes
                            (.toString (Sign/publicKeyFromPrivate
                                         (BigInteger. (apply str master-secret-key)
                                                      16))
                                       16))
        public-key (str "0488B21E"
                        "00"
                        "00000000"
                        "00000000"
                        master-chain-code
                        (if (= 0 (mod (nth master-public-key 63) 2))
                          "02"
                          "03")
                        (apply str (take 64 (codecs/bytes->hex master-public-key))))
        public-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                          (byte-array (codecs/hex->bytes public-key)))))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           (Base58/encode (codecs/hex->bytes (str private-key
                                                  (apply str (take 8 private-key-hash)))))))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           (Base58/encode (codecs/hex->bytes (str public-key
                                                  (apply str (take 8 public-key-hash)))))))))
