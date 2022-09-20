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

(deftest test-vector-1
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
        neutered-child (N child)
        base58-encoded-neutered-child-public-key (serialize :mainnet :public (:depth neutered-child)
                                                            fingerprint (:index neutered-child)
                                                            (:chain-code neutered-child)
                                                            (:public-key neutered-child))
        child-fingerprint (key-fingerprint (:public-key neutered-child))
        grandchildp (CKDpub neutered-child 1)
        base58-encoded-grandchild-public-key (serialize :mainnet :public (:depth grandchildp)
                                                        child-fingerprint (:index grandchildp)
                                                        (:chain-code grandchildp)
                                                        (:public-key grandchildp))
        grandchild (CKDpriv child 1)
        base58-encoded-grandchild-private-key (serialize :mainnet :private (:depth grandchild)
                                                         child-fingerprint (:index grandchild)
                                                         (:chain-code grandchild)
                                                         (:private-key grandchild))
        neutered-grandchild (N grandchild)
        base58-encoded-neutered-grandchild-public-key (serialize :mainnet :public (:depth neutered-grandchild)
                                                                 child-fingerprint (:index neutered-grandchild)
                                                                 (:chain-code neutered-grandchild)
                                                                 (:public-key neutered-grandchild))
        great-grandchild (CKDpriv grandchild (hardened 2))
        grandchild-fingerprint (key-fingerprint (:public-key neutered-grandchild))
        base58-encoded-great-grandchild-private-key (serialize :mainnet :private (:depth great-grandchild)
                                                               grandchild-fingerprint (:index great-grandchild)
                                                               (:chain-code great-grandchild)
                                                               (:private-key great-grandchild))
        neutered-great-grandchild (N great-grandchild)
        base58-encoded-great-grandchild-public-key (serialize :mainnet :public (:depth great-grandchild)
                                                              grandchild-fingerprint (:index great-grandchild)
                                                              (:chain-code neutered-great-grandchild)
                                                              (:public-key neutered-great-grandchild))
        great-great-grandchild (CKDpriv great-grandchild 2)
        great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-grandchild))
        base58-encoded-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-grandchild)
                                                                     great-grandchild-fingerprint (:index great-great-grandchild)
                                                                     (:chain-code great-great-grandchild)
                                                                     (:private-key great-great-grandchild))
        great-great-grandchildp (CKDpub neutered-great-grandchild 2)
        base58-encoded-great-great-grandchild-public-key (serialize :mainnet :public (:depth great-great-grandchildp)
                                                                    great-grandchild-fingerprint (:index great-great-grandchildp)
                                                                    (:chain-code great-great-grandchildp)
                                                                    (:public-key great-great-grandchildp))
        neutered-great-great-grandchild (N great-great-grandchild)
        base58-encoded-neutered-great-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-great-grandchild)
                                                                             great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                             (:chain-code neutered-great-great-grandchild)
                                                                             (:public-key neutered-great-great-grandchild))]
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           base58-encoded-public-key))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           base58-encoded-child-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           base58-encoded-neutered-child-public-key))
    (is (= "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
           base58-encoded-grandchild-private-key))
    (is (and (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                base58-encoded-grandchild-public-key)
             (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                base58-encoded-neutered-grandchild-public-key)))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2))))
    (is (= "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
           base58-encoded-great-grandchild-private-key))
    (is (= "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
           base58-encoded-great-grandchild-public-key))
    (is (= "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
           base58-encoded-great-great-grandchild-private-key))
    (is (and (= "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                base58-encoded-great-great-grandchild-public-key)
             (= "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                base58-encoded-neutered-great-great-grandchild-public-key)))))

(deftest test-vector-2
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
        neutered-child (N child)
        base58-encoded-neutered-child-public-key (serialize :mainnet :public (:depth neutered-child)
                                                            fingerprint (:index neutered-child)
                                                            (:chain-code neutered-child)
                                                            (:public-key neutered-child))
        grandchild (CKDpriv child (hardened 2147483647))
        child-fingerprint (key-fingerprint (:public-key childp))
        base58-encoded-grandchild-private-key (serialize :mainnet :private (:depth grandchild)
                                                         child-fingerprint (:index grandchild)
                                                         (:chain-code grandchild)
                                                         (:private-key grandchild))
        neutered-grandchild (N grandchild)
        base58-encoded-grandchild-public-key (serialize :mainnet :public (:depth neutered-grandchild)
                                                        child-fingerprint (:index neutered-grandchild)
                                                        (:chain-code neutered-grandchild)
                                                        (:public-key neutered-grandchild))
        great-grandchild (CKDpriv grandchild 1)
        grandchild-fingerprint (key-fingerprint (:public-key neutered-grandchild))
        base58-encoded-great-grandchild-private-key (serialize :mainnet :private (:depth great-grandchild)
                                                               grandchild-fingerprint (:index great-grandchild)
                                                               (:chain-code great-grandchild)
                                                               (:private-key great-grandchild))
        great-grandchildp (CKDpub neutered-grandchild 1)
        base58-encoded-great-grandchild-public-key (serialize :mainnet :public (:depth great-grandchildp)
                                                              grandchild-fingerprint (:index great-grandchildp)
                                                              (:chain-code great-grandchildp)
                                                              (:public-key great-grandchildp))
        neutered-great-grandchild (N great-grandchild)
        base58-encoded-neutered-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-grandchild)
                                                                       grandchild-fingerprint (:index neutered-great-grandchild)
                                                                       (:chain-code neutered-great-grandchild)
                                                                       (:public-key neutered-great-grandchild))
        great-great-grandchild (CKDpriv great-grandchild (hardened 2147483646))
        great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-grandchild))
        base58-encoded-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-grandchild)
                                                                     great-grandchild-fingerprint (:index great-great-grandchild)
                                                                     (:chain-code great-great-grandchild)
                                                                     (:private-key great-great-grandchild))
        neutered-great-great-grandchild (N great-great-grandchild)
        base58-encoded-neutered-great-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-great-grandchild)
                                                                             great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                             (:chain-code neutered-great-great-grandchild)
                                                                             (:public-key neutered-great-great-grandchild))]
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           base58-encoded-public-key))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           base58-encoded-child-private-key))
    (is (and (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                base58-encoded-child-public-key)
             (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                base58-encoded-neutered-child-public-key)))
    (is (= "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
           base58-encoded-grandchild-private-key))
    (is (= "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
           base58-encoded-grandchild-public-key))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2147483647))))
    (is (= "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
           base58-encoded-great-grandchild-private-key))
    (is (and (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                base58-encoded-neutered-great-grandchild-public-key)
             (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                base58-encoded-great-grandchild-public-key)))
    (is (= "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
           base58-encoded-great-great-grandchild-private-key))
    (is (= "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
           base58-encoded-neutered-great-great-grandchild-public-key))))
