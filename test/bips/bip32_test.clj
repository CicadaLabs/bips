(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [bips.bip32 :refer [derive-master-code CKDpriv CKDpub]]
    [clojure.math.numeric-tower :as math]
    [clojure.test :refer [deftest is]])
  (:import
    java.math.BigInteger
    (org.bitcoinj.core
      Base58
      Utils)
    org.web3j.crypto.Sign))

(deftest derive-master-code-ckd-priv-test-test-vector-1
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
        compressed-master-public-key (str (if (= 0 (mod (nth master-public-key 63) 2))
                                            "02"
                                            "03")
                                          (apply str (take 64 (codecs/bytes->hex master-public-key))))
        public-key (str "0488B21E"
                        "00"
                        "00000000"
                        "00000000"
                        master-chain-code
                        compressed-master-public-key)
        public-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                          (byte-array (codecs/hex->bytes public-key)))))
        I (CKDpriv master-secret-key master-chain-code (+ (math/expt 2 31) 0))
        child-private-key (.toString (.mod (.add (BigInteger. master-secret-key 16)
                                                 (BigInteger. 1 (byte-array (take 32 I))))
                                           (.getN Sign/CURVE_PARAMS))
                                     16)
        child-chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
        identifier (take 4 (Utils/sha256hash160 (codecs/hex->bytes compressed-master-public-key)))
        fingerprint (bit-or (bit-and (nth identifier 3) 0xFF)
                            (bit-shift-left (bit-and (nth identifier 2) 0xFF) 8)
                            (bit-shift-left (bit-and (nth identifier 1) 0xFF) 16)
                            (bit-shift-left (bit-and (first identifier) 0xFF) 24))
        formatted-child-private-key (str "0488ADE4"
                                         "01"
                                         (format "%x" fingerprint)
                                         (format "%08x" (+ (math/expt 2 31) 0))
                                         (apply str (take-last 64 child-chain-code))
                                         (str "00"
                                              (apply str (take (- 64 (count child-private-key)) (repeatedly #(identity "0"))))
                                              child-private-key))
        formatted-child-private-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                                           (byte-array (codecs/hex->bytes formatted-child-private-key)))))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           (Base58/encode (codecs/hex->bytes (str private-key
                                                  (apply str (take 8 private-key-hash)))))))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           (Base58/encode (codecs/hex->bytes (str public-key
                                                  (apply str (take 8 public-key-hash)))))))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           (Base58/encode (codecs/hex->bytes (str formatted-child-private-key
                                                  (apply str (take 8 formatted-child-private-key-hash)))))))))

(deftest derive-master-code-ckd-priv-test-test-vector-2
  (let [seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
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
        compressed-master-public-key (str (if (= 0 (mod (nth master-public-key 63) 2))
                                            "02"
                                            "03")
                                          (apply str (take 64 (codecs/bytes->hex master-public-key))))
        public-key (str "0488B21E"
                        "00"
                        "00000000"
                        "00000000"
                        master-chain-code
                        compressed-master-public-key)
        public-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                          (byte-array (codecs/hex->bytes public-key)))))
        I (CKDpriv master-secret-key master-chain-code 0)
        child-private-key (.toString (.mod (.add (BigInteger. master-secret-key 16)
                                                 (BigInteger. 1 (byte-array (take 32 I))))
                                           (.getN Sign/CURVE_PARAMS))
                                     16)
        child-chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
        identifier (take 4 (Utils/sha256hash160 (codecs/hex->bytes compressed-master-public-key)))
        fingerprint (bit-or (bit-and (nth identifier 3) 0xFF)
                            (bit-shift-left (bit-and (nth identifier 2) 0xFF) 8)
                            (bit-shift-left (bit-and (nth identifier 1) 0xFF) 16)
                            (bit-shift-left (bit-and (first identifier) 0xFF) 24))
        formatted-child-private-key (str "0488ADE4"
                                         "01"
                                         (format "%x" fingerprint)
                                         (format "%08x" 0)
                                         (apply str (take-last 64 child-chain-code))
                                         (str "00"
                                              (apply str (take (- 64 (count child-private-key)) (repeatedly #(identity "0"))))
                                              child-private-key))
        formatted-child-private-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                                           (byte-array (codecs/hex->bytes formatted-child-private-key)))))
        Ip (CKDpub compressed-master-public-key master-chain-code 0)
        Ki (.getEncoded (.add
                          (Sign/publicPointFromPrivate (BigInteger. 1 (byte-array (take 32 Ip))))
                          (Sign/publicPointFromPrivate (BigInteger. master-secret-key 16)))
                        true)
        ci (codecs/bytes->hex (byte-array (take-last 32 Ip)))
        formatted-child-public-key (str "0488B21E"
                                        "01"
                                        (format "%x" fingerprint)
                                        (format "%08x" 0)
                                        ci
                                        (codecs/bytes->hex Ki))
        formatted-child-public-key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                                          (byte-array (codecs/hex->bytes formatted-child-public-key)))))]
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           (Base58/encode (codecs/hex->bytes (str private-key
                                                  (apply str (take 8 private-key-hash)))))))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           (Base58/encode (codecs/hex->bytes (str public-key
                                                  (apply str (take 8 public-key-hash)))))))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           (Base58/encode (codecs/hex->bytes (str formatted-child-private-key
                                                  (apply str (take 8 formatted-child-private-key-hash)))))))
    (is (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
           (Base58/encode (codecs/hex->bytes (str formatted-child-public-key
                                                  (apply str (take 8 formatted-child-public-key-hash)))))))))
