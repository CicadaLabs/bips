(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [bips.bip32 :refer [derive-master-node CKDpriv CKDpub N]]
    [bips.bip32-utils :refer [hardened key-fingerprint serialize]]
    [clojure.math.numeric-tower :as math]
    [clojure.test :refer [deftest is]])
  (:import
    java.math.BigInteger
    org.web3j.crypto.Sign))

(deftest derive-master-code-ckd-priv-neutered-test-vector-1
  (let [seed "000102030405060708090a0b0c0d0e0f"
        master-node (derive-master-node seed)
        base58-encoded-private-key (serialize :mainnet :private (:depth master-node) 0 0
                                              (:chain-code master-node)
                                              (:private-key master-node))
        base58-encoded-public-key (serialize :mainnet :public 0 0 0
                                             (:chain-code master-node)
                                             (:public-key master-node))
        child (CKDpriv master-node (hardened 0))
        fingerprint (key-fingerprint (:public-key master-node))
        base58-encoded-child-private-key (serialize :mainnet :private (:depth child) fingerprint
                                                    (:index child)
                                                    (:chain-code child)
                                                    (:private-key child))
        neutered (N child)
        base58-encoded-neutered-child-public-key (serialize :mainnet :public (:depth neutered)
                                                            fingerprint (:index neutered)
                                                            (:chain-code neutered)
                                                            (:public-key neutered))
        grand-child (CKDpriv child 1)
        child-fingerprint (key-fingerprint (:public-key neutered))
        base58-encoded-grand-child-private-key (serialize :mainnet :private (:depth grand-child)
                                                          child-fingerprint (:index grand-child)
                                                          (:chain-code grand-child)
                                                          (:private-key grand-child))
        neutered-grand-child (N grand-child)
        base58-encoded-grand-child-public-key (serialize :mainnet :public (:depth grand-child)
                                                         child-fingerprint (:index grand-child)
                                                         (:chain-code neutered-grand-child)
                                                         (:public-key neutered-grand-child))
        grand-grand-child (CKDpriv grand-child (hardened 2))
        grand-child-fingerprint (key-fingerprint (:public-key neutered-grand-child))
        base58-encoded-grand-grand-child-private-key (serialize :mainnet :private (:depth grand-grand-child)
                                                                grand-child-fingerprint (:index grand-grand-child)
                                                                (:chain-code grand-grand-child)
                                                                (:private-key grand-grand-child))
        neutered-grand-grand-child (N grand-grand-child)
        base58-encoded-grand-grand-child-public-key (serialize :mainnet :public (:depth grand-grand-child)
                                                               grand-child-fingerprint (:index grand-grand-child)
                                                               (:chain-code neutered-grand-grand-child)
                                                               (:public-key neutered-grand-grand-child))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           base58-encoded-public-key))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           base58-encoded-child-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           base58-encoded-neutered-child-public-key))
    (is (= "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
           base58-encoded-grand-child-private-key))
    (is (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
           base58-encoded-grand-child-public-key))
    (is (= "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
           base58-encoded-grand-grand-child-private-key))
    (is (= "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
           base58-encoded-grand-grand-child-public-key))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2))))))

(deftest derive-master-code-ckd-priv-pub-neutered-test-vector-2
  (let [seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        master-node (derive-master-node seed)
        base58-encoded-private-key (serialize :mainnet :private (:depth master-node) 0 0
                                              (:chain-code master-node)
                                              (:private-key master-node))
        base58-encoded-public-key (serialize :mainnet :public 0 0 0
                                             (:chain-code master-node)
                                             (:public-key master-node))
        child (CKDpriv master-node 0)
        fingerprint (key-fingerprint (:public-key master-node))
        base58-encoded-child-private-key (serialize :mainnet :private (:depth child)
                                                    fingerprint (:index child)
                                                    (:chain-code child)
                                                    (:private-key child))
        childp (CKDpub master-node 0)
        base58-encoded-child-public-key (serialize :mainnet :public (:depth child)
                                                   fingerprint (:index child)
                                                   (:chain-code childp)
                                                   (:public-key childp))
        grand-child (CKDpriv child (hardened 2147483647))
        child-fingerprint (key-fingerprint (:public-key childp))
        base58-encoded-grand-child-private-key (serialize :mainnet :private (:depth grand-child)
                                                          child-fingerprint (:index grand-child)
                                                          (:chain-code grand-child)
                                                          (:private-key grand-child))
        neutered-grand-child (N grand-child)
        base58-encoded-grand-child-public-key (serialize :mainnet :public (:depth neutered-grand-child)
                                                         child-fingerprint (:index neutered-grand-child)
                                                         (:chain-code neutered-grand-child)
                                                         (:public-key neutered-grand-child))
        grand-grand-child (CKDpriv grand-child 1)
        grand-child-fingerprint (key-fingerprint (:public-key neutered-grand-child))
        base58-encoded-grand-grand-child-private-key (serialize :mainnet :private (:depth grand-grand-child)
                                                                grand-child-fingerprint (:index grand-grand-child)
                                                                (:chain-code grand-grand-child)
                                                                (:private-key grand-grand-child))
        neutered-grand-grand-child (N grand-grand-child)
        base58-encoded-grand-grand-child-public-key (serialize :mainnet :public (:depth neutered-grand-grand-child)
                                                               grand-child-fingerprint (:index neutered-grand-grand-child)
                                                               (:chain-code neutered-grand-grand-child)
                                                               (:public-key neutered-grand-grand-child))
        grand-grand-childp (CKDpub neutered-grand-child 1)
        base58-encoded-grand-grand-childp-public-key (serialize :mainnet :public (:depth grand-grand-childp)
                                                                grand-child-fingerprint (:index grand-grand-childp)
                                                                (:chain-code grand-grand-childp)
                                                                (:public-key grand-grand-childp))]
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           base58-encoded-public-key))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           base58-encoded-child-private-key))
    (is (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
           base58-encoded-child-public-key))
    (is (= "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
           base58-encoded-grand-child-private-key))
    (is (= "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
           base58-encoded-grand-child-public-key))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2147483647))))
    (is (= "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
           base58-encoded-grand-grand-child-private-key))
    (is (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
           base58-encoded-grand-grand-child-public-key))
    (is (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
           base58-encoded-grand-grand-childp-public-key))))
