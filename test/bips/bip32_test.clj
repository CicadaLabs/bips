(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [bips.bip32 :refer [derive-master-code CKDpriv CKDpub N]]
    [bips.bip32-utils :refer [key-fingerprint serialize]]
    [clojure.math.numeric-tower :as math]
    [clojure.test :refer [deftest is]])
  (:import
    java.math.BigInteger
    org.web3j.crypto.Sign))

(deftest derive-master-code-ckd-priv-neutered-test-vector-1
  (let [seed "000102030405060708090a0b0c0d0e0f"
        master-code (derive-master-code seed)
        master-secret-key (apply str (take 64 master-code))
        master-chain-code (apply str (take-last 64 master-code))
        private-key (serialize :mainnet :private 0 0 0
                               master-chain-code master-secret-key)
        master-public-key (codecs/hex->bytes
                            (.toString (Sign/publicKeyFromPrivate
                                         (BigInteger. (apply str master-secret-key)
                                                      16))
                                       16))
        public-key (serialize :mainnet :public 0 0 0
                              master-chain-code master-public-key)
        child (CKDpriv {:private-key master-secret-key
                        :chain-code master-chain-code
                        :index (+ (math/expt 2 31) 0)})
        fingerprint (key-fingerprint master-public-key)
        formatted-child-private-key (serialize :mainnet :private 1 fingerprint (math/expt 2 31)
                                               (:chain-code child)
                                               (:private-key child))
        neutered (N {:private-key (:private-key child)
                     :chain-code (:chain-code child)
                     :index 1})
        formatted-neutered-child-public-key (serialize :mainnet :public 1 fingerprint (math/expt 2 31)
                                                       (:chain-code neutered)
                                                       (:public-key neutered))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           public-key))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           formatted-child-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           formatted-neutered-child-public-key))))

(deftest derive-master-code-ckd-priv-pub-test-vector-2
  (let [seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        master-code (derive-master-code seed)
        master-secret-key (apply str (take 64 master-code))
        master-chain-code (apply str (take-last 64 master-code))
        private-key (serialize :mainnet :private 0 0 0
                               master-chain-code
                               master-secret-key)
        master-point-public-key (Sign/publicPointFromPrivate
                                  (BigInteger. (apply str master-secret-key)
                                               16))
        master-public-key (.getEncoded master-point-public-key false)
        public-key (serialize :mainnet :public 0 0 0
                              master-chain-code
                              (byte-array (take-last 64 master-public-key)))
        child (CKDpriv {:private-key master-secret-key
                        :chain-code master-chain-code
                        :index 0})
        fingerprint (key-fingerprint (byte-array (take-last 64 master-public-key)))
        formatted-child-private-key (serialize :mainnet :private 1 fingerprint 0
                                               (:chain-code child) (:private-key child))
        childp (CKDpub {:public-key (byte-array (take-last 64 master-public-key))
                        :chain-code master-chain-code
                        :index 0})
        formatted-child-public-key (serialize :mainnet :public 1 fingerprint 0
                                              (:chain-code childp)
                                              (byte-array (take-last 64 (:public-key childp))))]
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           public-key))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           formatted-child-private-key))
    (is (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
           formatted-child-public-key))))
