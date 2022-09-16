(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [bips.bip32 :refer [derive-master-node CKDpriv CKDpub N]]
    [bips.bip32-utils :refer [key-fingerprint serialize]]
    [clojure.math.numeric-tower :as math]
    [clojure.test :refer [deftest is]])
  (:import
    java.math.BigInteger
    org.web3j.crypto.Sign))

(deftest derive-master-code-ckd-priv-neutered-test-vector-1
  (let [seed "000102030405060708090a0b0c0d0e0f"
        master-node (derive-master-node seed)
        bip58-encoded-private-key (serialize :mainnet :private 0 0 0
                                             (:chain-code master-node)
                                             (:private-key master-node))
        bip58-encoded-public-key (serialize :mainnet :public 0 0 0
                                            (:chain-code master-node)
                                            (:public-key master-node))
        child (CKDpriv {:private-key (:private-key master-node)
                        :chain-code (:chain-code master-node)
                        :index (+ (math/expt 2 31) 0)})
        fingerprint (key-fingerprint (:public-key master-node))
        bip58-encoded-child-private-key (serialize :mainnet :private 1 fingerprint (math/expt 2 31)
                                                   (:chain-code child)
                                                   (:private-key child))
        neutered (N {:private-key (:private-key child)
                     :chain-code (:chain-code child)
                     :index 1})
        bip58-encoded-neutered-child-public-key (serialize :mainnet :public 1 fingerprint (math/expt 2 31)
                                                           (:chain-code neutered)
                                                           (:public-key neutered))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           bip58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           bip58-encoded-public-key))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           bip58-encoded-child-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           bip58-encoded-neutered-child-public-key))))

(deftest derive-master-code-ckd-priv-pub-test-vector-2
  (let [seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        master-node (derive-master-node seed)
        bip58-encoded-private-key (serialize :mainnet :private 0 0 0
                                             (:chain-code master-node)
                                             (:private-key master-node))
        bip58-encoded-public-key (serialize :mainnet :public 0 0 0
                                            (:chain-code master-node)
                                            (:public-key master-node))
        child (CKDpriv {:private-key (:private-key master-node)
                        :chain-code (:chain-code master-node)
                        :index 0})
        fingerprint (key-fingerprint (:public-key master-node))
        bip58-encoded-child-private-key (serialize :mainnet :private 1 fingerprint 0
                                                   (:chain-code child)
                                                   (:private-key child))
        childp (CKDpub {:public-key (:public-key master-node)
                        :chain-code (:chain-code master-node)
                        :index 0})
        bip58-encoded-child-public-key (serialize :mainnet :public 1 fingerprint 0
                                                  (:chain-code childp)
                                                  (:public-key childp))]
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           bip58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           bip58-encoded-public-key))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           bip58-encoded-child-private-key))
    (is (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
           bip58-encoded-child-public-key))))
