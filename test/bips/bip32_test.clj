(ns bips.bip32-test
  (:require
    [buddy.core.codecs :as codecs]
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
                              deserialize-base58
                              serialize
                              key-identifier
                              serialize-base58
                              encode-base58]]
    [bips.btc-utils :refer [privatekey->wif]]
    [clojure.test :refer [deftest is]]))

(deftest test-vector-1
  (let [seed "000102030405060708090a0b0c0d0e0f"
        ;; Chain m
        master-node-private-key (derive-path seed "m" :private)
        base58-encoded-master-node-private-key (serialize-base58 :mainnet :private (:depth master-node-private-key)
                                                                 0 0
                                                                 (:chain-code master-node-private-key)
                                                                 (:private-key master-node-private-key))
        master-node-public-key (derive-path seed "m" :public)
        serialized-master-node-public-key (serialize :mainnet :public (:depth master-node-public-key)
                                                     0 0
                                                     (:chain-code master-node-public-key)
                                                     (:public-key master-node-public-key))
        base58-encoded-master-node-public-key (serialize-base58 :mainnet :public (:depth master-node-public-key)
                                                                0 0
                                                                (:chain-code master-node-public-key)
                                                                (:public-key master-node-public-key))
        master-node (derive-master-node seed)
        serialized-master-node-private-key (serialize :mainnet :private (:depth master-node) 0 0
                                                      (:chain-code master-node)
                                                      (:private-key master-node))
        base58-encoded-private-key (serialize-base58 :mainnet :private (:depth master-node) 0 0
                                                     (:chain-code master-node)
                                                     (:private-key master-node))
        base58-encoded-public-key (serialize-base58 :mainnet :public 0 0 0
                                                    (:chain-code master-node)
                                                    (:public-key master-node))
        fingerprint (key-fingerprint (:public-key master-node))
        ;; Chain m/0H
        child-node-private-key (derive-path seed "m/0H" :private)
        base58-encoded-child-node-private-key (serialize-base58 :mainnet :private (:depth child-node-private-key) fingerprint
                                                                (:index child-node-private-key)
                                                                (:chain-code child-node-private-key)
                                                                (:private-key child-node-private-key))
        child-node-public-key (derive-path seed "m/0H" :public)
        base58-encoded-child-node-public-key (serialize-base58 :mainnet :public (:depth child-node-public-key)
                                                               fingerprint (:index child-node-public-key)
                                                               (:chain-code child-node-public-key)
                                                               (:public-key child-node-public-key))
        child (CKDpriv master-node (hardened 0))
        serialized-child-private-key (serialize :mainnet :private (:depth child) fingerprint
                                                (:index child)
                                                (:chain-code child)
                                                (:private-key child))
        base58-encoded-child-private-key (serialize-base58 :mainnet :private (:depth child) fingerprint
                                                           (:index child)
                                                           (:chain-code child)
                                                           (:private-key child))
        neutered-child (N child)
        serialized-child-public-key (serialize :mainnet :public (:depth neutered-child)
                                               fingerprint (:index neutered-child)
                                               (:chain-code neutered-child)
                                               (:public-key neutered-child))
        base58-encoded-neutered-child-public-key (serialize-base58 :mainnet :public (:depth neutered-child)
                                                                   fingerprint (:index neutered-child)
                                                                   (:chain-code neutered-child)
                                                                   (:public-key neutered-child))
        child-fingerprint (key-fingerprint (:public-key neutered-child))
        ;; Chain m/0H/1
        grandchild-node-private-key (derive-path seed "m/0H/1" :private)
        base58-encoded-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth grandchild-node-private-key)
                                                                     child-fingerprint
                                                                     (:index grandchild-node-private-key)
                                                                     (:chain-code grandchild-node-private-key)
                                                                     (:private-key grandchild-node-private-key))
        grandchild-node-public-key (derive-path seed "m/0H/1" :public)
        base58-encoded-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth grandchild-node-public-key)
                                                                    child-fingerprint
                                                                    (:index grandchild-node-public-key)
                                                                    (:chain-code grandchild-node-public-key)
                                                                    (:public-key grandchild-node-public-key))
        grandchildp (CKDpub neutered-child 1)
        base58-encoded-grandchild-public-key (serialize-base58 :mainnet :public (:depth grandchildp)
                                                               child-fingerprint (:index grandchildp)
                                                               (:chain-code grandchildp)
                                                               (:public-key grandchildp))
        grandchild (CKDpriv child 1)
        serialized-grandchild-private-key (serialize :mainnet :private (:depth grandchild)
                                                     child-fingerprint (:index grandchild)
                                                     (:chain-code grandchild)
                                                     (:private-key grandchild))
        base58-encoded-grandchild-private-key (serialize-base58 :mainnet :private (:depth grandchild)
                                                                child-fingerprint (:index grandchild)
                                                                (:chain-code grandchild)
                                                                (:private-key grandchild))
        neutered-grandchild (N grandchild)
        serialized-grandchild-public-key (serialize :mainnet :public (:depth neutered-grandchild)
                                                    child-fingerprint (:index neutered-grandchild)
                                                    (:chain-code neutered-grandchild)
                                                    (:public-key neutered-grandchild))
        base58-encoded-neutered-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-grandchild)
                                                                        child-fingerprint (:index neutered-grandchild)
                                                                        (:chain-code neutered-grandchild)
                                                                        (:public-key neutered-grandchild))
        grandchild-fingerprint (key-fingerprint (:public-key neutered-grandchild))
        ;; Chain m/0H/1/2H
        great-grandchild-node-private-key (derive-path seed "m/0H/1/2H" :private)
        base58-encoded-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-grandchild-node-private-key)
                                                                           grandchild-fingerprint (:index great-grandchild-node-private-key)
                                                                           (:chain-code great-grandchild-node-private-key)
                                                                           (:private-key great-grandchild-node-private-key))
        great-grandchild-node-public-key (derive-path seed "m/0H/1/2H" :public)
        base58-encoded-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-grandchild-node-public-key)
                                                                          grandchild-fingerprint (:index great-grandchild-node-public-key)
                                                                          (:chain-code great-grandchild-node-public-key)
                                                                          (:public-key great-grandchild-node-public-key))
        great-grandchild (CKDpriv grandchild (hardened 2))
        serialized-great-grandchild-private-key (serialize :mainnet :private (:depth great-grandchild)
                                                           grandchild-fingerprint (:index great-grandchild)
                                                           (:chain-code great-grandchild)
                                                           (:private-key great-grandchild))
        base58-encoded-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-grandchild)
                                                                      grandchild-fingerprint (:index great-grandchild)
                                                                      (:chain-code great-grandchild)
                                                                      (:private-key great-grandchild))
        neutered-great-grandchild (N great-grandchild)
        serialized-great-grandchild-public-key (serialize :mainnet :public (:depth great-grandchild)
                                                          grandchild-fingerprint (:index great-grandchild)
                                                          (:chain-code neutered-great-grandchild)
                                                          (:public-key neutered-great-grandchild))
        base58-encoded-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth great-grandchild)
                                                                     grandchild-fingerprint (:index great-grandchild)
                                                                     (:chain-code neutered-great-grandchild)
                                                                     (:public-key neutered-great-grandchild))
        great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-grandchild))
        ;; Chain m/0H/1/2H/2
        great-great-grandchild-node-private-key (derive-path seed "m/0H/1/2H/2" :private)
        base58-encoded-great-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-great-grandchild-node-private-key)
                                                                                 great-grandchild-fingerprint (:index great-great-grandchild-node-private-key)
                                                                                 (:chain-code great-great-grandchild-node-private-key)
                                                                                 (:private-key great-great-grandchild-node-private-key))
        great-great-grandchild-node-public-key (derive-path seed "m/0H/1/2H/2" :public)
        base58-encoded-great-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-great-grandchild-node-public-key)
                                                                                great-grandchild-fingerprint (:index great-great-grandchild-node-public-key)
                                                                                (:chain-code great-great-grandchild-node-public-key)
                                                                                (:public-key great-great-grandchild-node-public-key))
        great-great-grandchild (CKDpriv great-grandchild 2)
        serialized-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-grandchild)
                                                                 great-grandchild-fingerprint (:index great-great-grandchild)
                                                                 (:chain-code great-great-grandchild)
                                                                 (:private-key great-great-grandchild))
        base58-encoded-great-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-great-grandchild)
                                                                            great-grandchild-fingerprint (:index great-great-grandchild)
                                                                            (:chain-code great-great-grandchild)
                                                                            (:private-key great-great-grandchild))
        great-great-grandchildp (CKDpub neutered-great-grandchild 2)
        base58-encoded-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth great-great-grandchildp)
                                                                           great-grandchild-fingerprint (:index great-great-grandchildp)
                                                                           (:chain-code great-great-grandchildp)
                                                                           (:public-key great-great-grandchildp))
        neutered-great-great-grandchild (N great-great-grandchild)
        serialized-great-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-great-grandchild)
                                                                great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                (:chain-code neutered-great-great-grandchild)
                                                                (:public-key neutered-great-great-grandchild))
        base58-encoded-neutered-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-great-great-grandchild)
                                                                                    great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                                    (:chain-code neutered-great-great-grandchild)
                                                                                    (:public-key neutered-great-great-grandchild))
        great-great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-great-grandchild))
        ;; Chain m/0H/1/2H/2/1000000000
        great-great-great-grandchild-node-private-key (derive-path seed "m/0H/1/2H/2/1000000000" :private)
        base58-encoded-great-great-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-great-great-grandchild-node-private-key)
                                                                                       great-great-grandchild-fingerprint (:index great-great-great-grandchild-node-private-key)
                                                                                       (:chain-code great-great-great-grandchild-node-private-key)
                                                                                       (:private-key great-great-great-grandchild-node-private-key))
        great-great-great-grandchild-node-public-key (derive-path seed "m/0H/1/2H/2/1000000000" :public)
        base58-encoded-great-great-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-great-great-grandchild-node-public-key)
                                                                                      great-great-grandchild-fingerprint (:index great-great-great-grandchild-node-public-key)
                                                                                      (:chain-code great-great-great-grandchild-node-public-key)
                                                                                      (:public-key great-great-great-grandchild-node-public-key))
        great-great-great-grandchild (CKDpriv great-great-grandchild 1000000000)
        serialized-great-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-great-grandchild)
                                                                       great-great-grandchild-fingerprint (:index great-great-great-grandchild)
                                                                       (:chain-code great-great-great-grandchild)
                                                                       (:private-key great-great-great-grandchild))
        base58-encoded-great-great-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-great-great-grandchild)
                                                                                  great-great-grandchild-fingerprint (:index great-great-great-grandchild)
                                                                                  (:chain-code great-great-great-grandchild)
                                                                                  (:private-key great-great-great-grandchild))
        neutered-great-great-great-grandchild (N great-great-great-grandchild)
        serialized-great-great-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-great-great-grandchild)
                                                                      great-great-grandchild-fingerprint (:index neutered-great-great-great-grandchild)
                                                                      (:chain-code neutered-great-great-great-grandchild)
                                                                      (:public-key neutered-great-great-great-grandchild))
        base58-encoded-neutered-great-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-great-great-great-grandchild)
                                                                                          great-great-grandchild-fingerprint (:index neutered-great-great-great-grandchild)
                                                                                          (:chain-code neutered-great-great-great-grandchild)
                                                                                          (:public-key neutered-great-great-great-grandchild))
        great-great-great-grandchildp (CKDpub neutered-great-great-grandchild 1000000000)
        base58-encoded-great-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth great-great-great-grandchildp)
                                                                                 great-great-grandchild-fingerprint (:index great-great-great-grandchildp)
                                                                                 (:chain-code great-great-great-grandchildp)
                                                                                 (:public-key great-great-great-grandchildp))]
    ;; Chain m
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           base58-encoded-public-key))
    (is (= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
           base58-encoded-master-node-private-key))
    (is (= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
           base58-encoded-master-node-public-key))
    (is (= "3442193e1bb70916e914552172cd4e2dbc9df811"
           (codecs/bytes->hex (key-identifier (:public-key master-node)))))
    (is (= (Long/parseLong "3442193e" 16)
           (key-fingerprint (:public-key master-node))))
    (is (= "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier (:public-key master-node)))))))))
    (is (= "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
           (:private-key master-node)))
    (is (= "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"
           (privatekey->wif (:private-key master-node)
                            :mainnet true)))
    (is (= "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
           (:public-key master-node)))
    (is (= "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
           (:chain-code master-node)))
    (is (= "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
           serialized-master-node-public-key))
    (is (= "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
           serialized-master-node-private-key))
    ;; Chain m/0H
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           base58-encoded-child-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           base58-encoded-neutered-child-public-key))
    (is (= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
           base58-encoded-child-node-private-key))
    (is (= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
           base58-encoded-child-node-public-key))
    (is (= "5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7"
           (codecs/bytes->hex (key-identifier (:public-key neutered-child)))))
    (is (= (Long/parseLong "5c1bd648" 16)
           (key-fingerprint (:public-key neutered-child))))
    (is (= "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier (:public-key neutered-child)))))))))
    (is (= "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
           (:private-key child)))
    (is (= "L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT"
           (privatekey->wif (:private-key child) :mainnet true)))
    (is (= "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
           (:public-key neutered-child)))
    (is (= "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
           (:chain-code child)))
    (is (= "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
           serialized-child-public-key))
    (is (= "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
           serialized-child-private-key))
    ;; Chain m/0H/1
    (is (= "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
           base58-encoded-grandchild-private-key))
    (is (and (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                base58-encoded-grandchild-public-key)
             (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                base58-encoded-neutered-grandchild-public-key)))
    (is (= "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
           base58-encoded-grandchild-node-private-key))
    (is (= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
           base58-encoded-grandchild-node-public-key))
    (is (= "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe"
           (codecs/bytes->hex (key-identifier (:public-key neutered-grandchild)))))
    (is (= (Long/parseLong "bef5a2f9" 16)
           (key-fingerprint (:public-key neutered-grandchild))))
    (is (= "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier
                                                      (:public-key neutered-grandchild)))))))))
    (is (= "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
           (:private-key grandchild)))
    (is (= "KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM"
           (privatekey->wif (:private-key grandchild) :mainnet true)))
    (is (= "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
           (:public-key neutered-grandchild)))
    (is (= "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
           (:chain-code grandchild)))
    (is (= "0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
           serialized-grandchild-public-key))
    (is (= "0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
           serialized-grandchild-private-key))
    ;; Chain m/0H/1/2H
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2))))
    (is (= "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
           base58-encoded-great-grandchild-private-key))
    (is (= "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
           base58-encoded-great-grandchild-public-key))
    (is (= "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
           base58-encoded-great-grandchild-node-private-key))
    (is (= "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
           base58-encoded-great-grandchild-node-public-key))
    (is (= "ee7ab90cde56a8c0e2bb086ac49748b8db9dce72"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-grandchild)))))
    (is (= (Long/parseLong "ee7ab90c" 16)
           (key-fingerprint (:public-key neutered-great-grandchild))))
    (is (= "1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex
                                   (key-identifier (:public-key neutered-great-grandchild))))))))
    (is (= "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
           (:private-key great-grandchild)))
    (is (= "L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU"
           (privatekey->wif (:private-key great-grandchild) :mainnet true)))
    (is (= "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
           (:public-key neutered-great-grandchild)))
    (is (= "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"
           (:chain-code great-grandchild)))
    (is (= "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
           serialized-great-grandchild-public-key))
    (is (= "0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
           serialized-great-grandchild-private-key))
    ;; Chain m/0H/1/2H/2
    (is (= "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
           base58-encoded-great-great-grandchild-private-key))
    (is (and (= "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                base58-encoded-great-great-grandchild-public-key)
             (= "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                base58-encoded-neutered-great-great-grandchild-public-key)))
    (is (= "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
           base58-encoded-great-great-grandchild-node-private-key))
    (is (= "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
           base58-encoded-great-great-grandchild-node-public-key))
    (is (= "d880d7d893848509a62d8fb74e32148dac68412f"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-grandchild)))))
    (is (= (Long/parseLong "d880d7d8" 16)
           (key-fingerprint (:public-key neutered-great-great-grandchild))))
    (is (= "1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex
                                   (key-identifier (:public-key neutered-great-great-grandchild))))))))
    (is (= "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
           (:private-key great-great-grandchild)))
    (is (= "KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR"
           (privatekey->wif (:private-key great-great-grandchild) :mainnet true)))
    (is (= "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
           (:public-key neutered-great-great-grandchild)))
    (is (= "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
           (:chain-code great-great-grandchild)))
    (is (= "0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
           serialized-great-great-grandchild-public-key))
    (is (= "0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
           serialized-great-great-grandchild-private-key))
    ;; Chain m/0H/1/2H/2/1000000000
    (is (= "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
           base58-encoded-great-great-great-grandchild-private-key))
    (is (and (= "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                base58-encoded-neutered-great-great-great-grandchild-public-key)
             (= "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                base58-encoded-great-great-great-grandchild-public-key)))
    (is (= "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
           base58-encoded-great-great-great-grandchild-node-private-key))
    (is (= "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
           base58-encoded-great-great-great-grandchild-node-public-key))
    (is (= "d69aa102255fed74378278c7812701ea641fdf32"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-great-grandchild)))))
    (is (= (Long/parseLong "d69aa102" 16)
           (key-fingerprint (:public-key neutered-great-great-great-grandchild))))
    (is (= "1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex
                                   (key-identifier (:public-key neutered-great-great-great-grandchild))))))))
    (is (= "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
           (:private-key great-great-great-grandchild)))
    (is (= "Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs"
           (privatekey->wif (:private-key great-great-great-grandchild) :mainnet true)))
    (is (= "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
           (:public-key neutered-great-great-great-grandchild)))
    (is (= "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
           (:chain-code great-great-great-grandchild)))
    (is (= "0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
           serialized-great-great-great-grandchild-public-key))
    (is (= "0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
           serialized-great-great-great-grandchild-private-key))))

(deftest test-vector-2
  (let [seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ;; Chain m
        master-node-private-key (derive-path seed "m" :private)
        serialized-master-node-private-key (serialize :mainnet :private (:depth master-node-private-key)
                                                      0 0
                                                      (:chain-code master-node-private-key)
                                                      (:private-key master-node-private-key))
        base58-encoded-master-node-private-key (serialize-base58 :mainnet :private (:depth master-node-private-key)
                                                                 0 0
                                                                 (:chain-code master-node-private-key)
                                                                 (:private-key master-node-private-key))
        master-node-public-key (derive-path seed "m" :public)
        serialized-master-node-public-key (serialize :mainnet :public (:depth master-node-public-key)
                                                     0 0
                                                     (:chain-code master-node-public-key)
                                                     (:public-key master-node-public-key))
        base58-encoded-master-node-public-key (serialize-base58 :mainnet :public (:depth master-node-public-key)
                                                                0 0
                                                                (:chain-code master-node-public-key)
                                                                (:public-key master-node-public-key))
        master-node (derive-master-node seed)
        base58-encoded-private-key (serialize-base58 :mainnet :private (:depth master-node) 0 0
                                                     (:chain-code master-node)
                                                     (:private-key master-node))
        base58-encoded-public-key (serialize-base58 :mainnet :public 0 0 0
                                                    (:chain-code master-node)
                                                    (:public-key master-node))
        fingerprint (key-fingerprint (:public-key master-node))
        ;; Chain m/0
        child-node-private-key (derive-path seed "m/0" :private)
        base58-encoded-child-node-private-key (serialize-base58 :mainnet :private (:depth child-node-private-key) fingerprint
                                                                (:index child-node-private-key)
                                                                (:chain-code child-node-private-key)
                                                                (:private-key child-node-private-key))
        child-node-public-key (derive-path seed "m/0" :public)
        base58-encoded-child-node-public-key (serialize-base58 :mainnet :public (:depth child-node-public-key)
                                                               fingerprint (:index child-node-public-key)
                                                               (:chain-code child-node-public-key)
                                                               (:public-key child-node-public-key))
        child (CKDpriv master-node 0)
        serialized-child-private-key (serialize :mainnet :private (:depth child)
                                                fingerprint (:index child)
                                                (:chain-code child)
                                                (:private-key child))
        base58-encoded-child-private-key (serialize-base58 :mainnet :private (:depth child)
                                                           fingerprint (:index child)
                                                           (:chain-code child)
                                                           (:private-key child))
        childp (CKDpub master-node 0)
        serialized-child-public-key (serialize :mainnet :public (:depth child)
                                               fingerprint (:index child)
                                               (:chain-code childp)
                                               (:public-key childp))
        base58-encoded-child-public-key (serialize-base58 :mainnet :public (:depth child)
                                                          fingerprint (:index child)
                                                          (:chain-code childp)
                                                          (:public-key childp))
        neutered-child (N child)
        base58-encoded-neutered-child-public-key (serialize-base58 :mainnet :public (:depth neutered-child)
                                                                   fingerprint (:index neutered-child)
                                                                   (:chain-code neutered-child)
                                                                   (:public-key neutered-child))
        child-fingerprint (key-fingerprint (:public-key childp))
        ;; Chain m/0/2147483647H
        grandchild-node-private-key (derive-path seed "m/0/2147483647H" :private)
        base58-encoded-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth grandchild-node-private-key)
                                                                     child-fingerprint
                                                                     (:index grandchild-node-private-key)
                                                                     (:chain-code grandchild-node-private-key)
                                                                     (:private-key grandchild-node-private-key))
        grandchild-node-public-key (derive-path seed "m/0/2147483647H" :public)
        base58-encoded-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth grandchild-node-public-key)
                                                                    child-fingerprint
                                                                    (:index grandchild-node-public-key)
                                                                    (:chain-code grandchild-node-public-key)
                                                                    (:public-key grandchild-node-public-key))
        grandchild (CKDpriv child (hardened 2147483647))
        serialized-grandchild-private-key (serialize :mainnet :private (:depth grandchild)
                                                     child-fingerprint (:index grandchild)
                                                     (:chain-code grandchild)
                                                     (:private-key grandchild))
        base58-encoded-grandchild-private-key (serialize-base58 :mainnet :private (:depth grandchild)
                                                                child-fingerprint (:index grandchild)
                                                                (:chain-code grandchild)
                                                                (:private-key grandchild))
        neutered-grandchild (N grandchild)
        serialized-grandchild-public-key (serialize :mainnet :public (:depth neutered-grandchild)
                                                    child-fingerprint (:index neutered-grandchild)
                                                    (:chain-code neutered-grandchild)
                                                    (:public-key neutered-grandchild))
        base58-encoded-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-grandchild)
                                                               child-fingerprint (:index neutered-grandchild)
                                                               (:chain-code neutered-grandchild)
                                                               (:public-key neutered-grandchild))
        grandchild-fingerprint (key-fingerprint (:public-key neutered-grandchild))
        ;; Chain m/0/2147483647H/1
        great-grandchild-node-private-key (derive-path seed "m/0/2147483647H/1" :private)
        base58-encoded-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-grandchild-node-private-key)
                                                                           grandchild-fingerprint (:index great-grandchild-node-private-key)
                                                                           (:chain-code great-grandchild-node-private-key)
                                                                           (:private-key great-grandchild-node-private-key))
        great-grandchild-node-public-key (derive-path seed "m/0/2147483647H/1" :public)
        base58-encoded-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-grandchild-node-public-key)
                                                                          grandchild-fingerprint (:index great-grandchild-node-public-key)
                                                                          (:chain-code great-grandchild-node-public-key)
                                                                          (:public-key great-grandchild-node-public-key))
        great-grandchild (CKDpriv grandchild 1)
        serialized-great-grandchild-private-key (serialize :mainnet :private (:depth great-grandchild)
                                                           grandchild-fingerprint (:index great-grandchild)
                                                           (:chain-code great-grandchild)
                                                           (:private-key great-grandchild))
        base58-encoded-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-grandchild)
                                                                      grandchild-fingerprint (:index great-grandchild)
                                                                      (:chain-code great-grandchild)
                                                                      (:private-key great-grandchild))
        great-grandchildp (CKDpub neutered-grandchild 1)
        base58-encoded-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth great-grandchildp)
                                                                     grandchild-fingerprint (:index great-grandchildp)
                                                                     (:chain-code great-grandchildp)
                                                                     (:public-key great-grandchildp))
        neutered-great-grandchild (N great-grandchild)
        serialized-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-grandchild)
                                                          grandchild-fingerprint (:index neutered-great-grandchild)
                                                          (:chain-code neutered-great-grandchild)
                                                          (:public-key neutered-great-grandchild))
        base58-encoded-neutered-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-great-grandchild)
                                                                              grandchild-fingerprint (:index neutered-great-grandchild)
                                                                              (:chain-code neutered-great-grandchild)
                                                                              (:public-key neutered-great-grandchild))
        great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-grandchild))
        ;; Chain m/0/2147483647H/1/2147483646H
        great-great-grandchild-node-private-key (derive-path seed "m/0/2147483647H/1/2147483646H" :private)
        base58-encoded-great-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-great-grandchild-node-private-key)
                                                                                 great-grandchild-fingerprint (:index great-great-grandchild-node-private-key)
                                                                                 (:chain-code great-great-grandchild-node-private-key)
                                                                                 (:private-key great-great-grandchild-node-private-key))
        great-great-grandchild-node-public-key (derive-path seed "m/0/2147483647H/1/2147483646H" :public)
        base58-encoded-great-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-great-grandchild-node-public-key)
                                                                                great-grandchild-fingerprint (:index great-great-grandchild-node-public-key)
                                                                                (:chain-code great-great-grandchild-node-public-key)
                                                                                (:public-key great-great-grandchild-node-public-key))
        great-great-grandchild (CKDpriv great-grandchild (hardened 2147483646))
        serialized-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-grandchild)
                                                                 great-grandchild-fingerprint (:index great-great-grandchild)
                                                                 (:chain-code great-great-grandchild)
                                                                 (:private-key great-great-grandchild))
        base58-encoded-great-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-great-grandchild)
                                                                            great-grandchild-fingerprint (:index great-great-grandchild)
                                                                            (:chain-code great-great-grandchild)
                                                                            (:private-key great-great-grandchild))
        neutered-great-great-grandchild (N great-great-grandchild)
        serialized-great-great-grandchild-public-key (serialize :mainnet :public (:depth neutered-great-great-grandchild)
                                                                great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                (:chain-code neutered-great-great-grandchild)
                                                                (:public-key neutered-great-great-grandchild))
        base58-encoded-neutered-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-great-great-grandchild)
                                                                                    great-grandchild-fingerprint (:index neutered-great-great-grandchild)
                                                                                    (:chain-code neutered-great-great-grandchild)
                                                                                    (:public-key neutered-great-great-grandchild))
        great-great-grandchild-fingerprint (key-fingerprint (:public-key neutered-great-great-grandchild))
        ;; Chain m/0/2147483647H/1/2147483646H/2
        great-great-great-grandchild-node-private-key (derive-path seed "m/0/2147483647H/1/2147483646H/2" :private)
        base58-encoded-great-great-great-grandchild-node-private-key (serialize-base58 :mainnet :private (:depth great-great-great-grandchild-node-private-key)
                                                                                       great-great-grandchild-fingerprint (:index great-great-great-grandchild-node-private-key)
                                                                                       (:chain-code great-great-great-grandchild-node-private-key)
                                                                                       (:private-key great-great-great-grandchild-node-private-key))
        great-great-great-grandchild-node-public-key (derive-path seed "m/0/2147483647H/1/2147483646H/2" :public)
        base58-encoded-great-great-great-grandchild-node-public-key (serialize-base58 :mainnet :public (:depth great-great-great-grandchild-node-public-key)
                                                                                      great-great-grandchild-fingerprint (:index great-great-great-grandchild-node-public-key)
                                                                                      (:chain-code great-great-great-grandchild-node-public-key)
                                                                                      (:public-key great-great-great-grandchild-node-public-key))
        great-great-great-grandchild (CKDpriv great-great-grandchild 2)
        serialized-great-great-great-grandchild-private-key (serialize :mainnet :private (:depth great-great-great-grandchild)
                                                                       great-great-grandchild-fingerprint (:index great-great-great-grandchild)
                                                                       (:chain-code great-great-great-grandchild)
                                                                       (:private-key great-great-great-grandchild))
        base58-encoded-great-great-great-grandchild-private-key (serialize-base58 :mainnet :private (:depth great-great-great-grandchild)
                                                                                  great-great-grandchild-fingerprint (:index great-great-great-grandchild)
                                                                                  (:chain-code great-great-great-grandchild)
                                                                                  (:private-key great-great-great-grandchild))
        neutered-great-great-great-grandchild (N great-great-great-grandchild)

        base58-encoded-neutered-great-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth neutered-great-great-great-grandchild)
                                                                                          great-great-grandchild-fingerprint (:index neutered-great-great-great-grandchild)
                                                                                          (:chain-code neutered-great-great-great-grandchild)
                                                                                          (:public-key neutered-great-great-great-grandchild))
        great-great-great-grandchildp (CKDpub neutered-great-great-grandchild 2)
        serialized-great-great-great-grandchild-public-key (serialize :mainnet :public (:depth great-great-great-grandchildp)
                                                                      great-great-grandchild-fingerprint (:index great-great-great-grandchildp)
                                                                      (:chain-code great-great-great-grandchildp)
                                                                      (:public-key great-great-great-grandchildp))
        base58-encoded-great-great-great-grandchild-public-key (serialize-base58 :mainnet :public (:depth great-great-great-grandchildp)
                                                                                 great-great-grandchild-fingerprint (:index great-great-great-grandchildp)
                                                                                 (:chain-code great-great-great-grandchildp)
                                                                                 (:public-key great-great-great-grandchildp))]
    ;; Chain m
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           base58-encoded-private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           base58-encoded-public-key))
    (is (= "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
           base58-encoded-master-node-private-key))
    (is (= "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
           base58-encoded-master-node-public-key))
    (is (= "bd16bee53961a47d6ad888e29545434a89bdfe95"
           (codecs/bytes->hex (key-identifier (:public-key master-node)))))
    (is (= (Long/parseLong "bd16bee5" 16)
           (key-fingerprint (:public-key master-node))))
    (is (= "1JEoxevbLLG8cVqeoGKQiAwoWbNYSUyYjg"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier (:public-key master-node)))))))))
    (is (= "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
           (:private-key master-node)))
    (is (= "KyjXhyHF9wTphBkfpxjL8hkDXDUSbE3tKANT94kXSyh6vn6nKaoy"
           (privatekey->wif (:private-key master-node) :mainnet true)))
    (is (= "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
           (:public-key master-node)))
    (is (= "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
           (:chain-code master-node)))
    (is (= "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
           serialized-master-node-public-key))
    (is (= "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
           serialized-master-node-private-key))
    ;; Chain m/0
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           base58-encoded-child-private-key))
    (is (and (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                base58-encoded-child-public-key)
             (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                base58-encoded-neutered-child-public-key)))
    (is (= "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
           base58-encoded-child-node-private-key))
    (is (= "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
           base58-encoded-child-node-public-key))
    (is (= "5a61ff8eb7aaca3010db97ebda76121610b78096"
           (codecs/bytes->hex (key-identifier (:public-key neutered-child)))))
    (is (= (Long/parseLong "5a61ff8e" 16)
           (key-fingerprint (:public-key neutered-child))))
    (is (= "19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier (:public-key neutered-child)))))))))
    (is (= "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
           (:private-key child)))
    (is (= "L2ysLrR6KMSAtx7uPqmYpoTeiRzydXBattRXjXz5GDFPrdfPzKbj"
           (privatekey->wif (:private-key child) :mainnet true)))
    (is (= "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
           (:public-key neutered-child)))
    (is (= "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
           (:chain-code child)))
    (is (= "0488b21e01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
           serialized-child-public-key))
    (is (= "0488ade401bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
           serialized-child-private-key))
    ;; Chain m/0/2147483647H
    (is (= "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
           base58-encoded-grandchild-private-key))
    (is (= "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
           base58-encoded-grandchild-public-key))
    (is (thrown-with-msg? Exception #"Cannot derive a public key for hardened child keys."
          (CKDpub child (hardened 2147483647))))
    (is (= "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
           base58-encoded-grandchild-node-private-key))
    (is (= "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
           base58-encoded-grandchild-node-public-key))
    (is (= "d8ab493736da02f11ed682f88339e720fb0379d1"
           (codecs/bytes->hex (key-identifier (:public-key neutered-grandchild)))))
    (is (= (Long/parseLong "d8ab4937" 16)
           (key-fingerprint (:public-key neutered-grandchild))))
    (is (= "1Lke9bXGhn5VPrBuXgN12uGUphrttUErmk"
           (encode-base58 (byte-array (codecs/hex->bytes
                                        (str "00" (codecs/bytes->hex
                                                    (key-identifier (:public-key neutered-grandchild)))))))))
    (is (= "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
           (:private-key grandchild)))
    (is (= "L1m5VpbXmMp57P3knskwhoMTLdhAAaXiHvnGLMribbfwzVRpz2Sr"
           (privatekey->wif (:private-key grandchild) :mainnet true)))
    (is (= "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"
           (:public-key neutered-grandchild)))
    (is (= "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9"
           (:chain-code grandchild)))
    (is (= "0488b21e025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"
           serialized-grandchild-public-key))
    (is (= "0488ade4025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
           serialized-grandchild-private-key))
    ;; Chain m/0/2147483647H/1
    (is (= "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
           base58-encoded-great-grandchild-private-key))
    (is (and (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                base58-encoded-neutered-great-grandchild-public-key)
             (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                base58-encoded-great-grandchild-public-key)))
    (is (= "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
           base58-encoded-great-grandchild-node-private-key))
    (is (= "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
           base58-encoded-great-grandchild-node-public-key))
    (is (= "78412e3a2296a40de124307b6485bd19833e2e34"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-grandchild)))))
    (is (= (Long/parseLong "78412e3a" 16)
           (key-fingerprint (:public-key neutered-great-grandchild))))
    (is (= "1BxrAr2pHpeBheusmd6fHDP2tSLAUa3qsW"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex (key-identifier (:public-key neutered-great-grandchild))))))))
    (is (= "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
           (:private-key great-grandchild)))
    (is (= "KzyzXnznxSv249b4KuNkBwowaN3akiNeEHy5FWoPCJpStZbEKXN2"
           (privatekey->wif (:private-key great-grandchild) :mainnet true)))
    (is (= "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"
           (:public-key neutered-great-grandchild)))
    (is (= "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb"
           (:chain-code great-grandchild)))
    (is (= "0488b21e03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"
           serialized-great-grandchild-public-key))
    (is (= "0488ade403d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb00704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
           serialized-great-grandchild-private-key))
    ;; Chain m/0/2147483647H/1/2147483646H
    (is (= "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
           base58-encoded-great-great-grandchild-private-key))
    (is (= "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
           base58-encoded-neutered-great-great-grandchild-public-key))
    (is (= "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
           base58-encoded-great-great-grandchild-node-private-key))
    (is (= "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
           base58-encoded-great-great-grandchild-node-public-key))
    (is (= "31a507b815593dfc51ffc7245ae7e5aee304246e"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-grandchild)))))
    (is (= (Long/parseLong "31a507b8" 16)
           (key-fingerprint (:public-key neutered-great-great-grandchild))))
    (is (= "15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-grandchild))))))))
    (is (= "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
           (:private-key great-great-grandchild)))
    (is (= "L5KhaMvPYRW1ZoFmRjUtxxPypQ94m6BcDrPhqArhggdaTbbAFJEF"
           (privatekey->wif (:private-key great-great-grandchild) :mainnet true)))
    (is (= "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
           (:public-key neutered-great-great-grandchild)))
    (is (= "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
           (:chain-code great-great-grandchild)))
    (is (= "0488b21e0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2902d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
           serialized-great-great-grandchild-public-key))
    (is (= "0488ade40478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2900f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
           serialized-great-great-grandchild-private-key))
    ;; Chain m/0/2147483647H/1/2147483646H/2
    (is (= "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
           base58-encoded-great-great-great-grandchild-private-key))
    (is (and (= "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
                base58-encoded-neutered-great-great-great-grandchild-public-key)
             (= "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
                base58-encoded-great-great-great-grandchild-public-key)))
    (is (= "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
           base58-encoded-great-great-great-grandchild-node-private-key))
    (is (= "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
           base58-encoded-great-great-great-grandchild-node-public-key))
    (is (= "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
           (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-great-grandchild)))))
    (is (= (Long/parseLong "26132fdb" 16)
           (key-fingerprint (:public-key neutered-great-great-great-grandchild))))
    (is (= "14UKfRV9ZPUp6ZC9PLhqbRtxdihW9em3xt"
           (encode-base58 (codecs/hex->bytes
                            (str "00"
                                 (codecs/bytes->hex (key-identifier (:public-key neutered-great-great-great-grandchild))))))))
    (is (= "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
           (:private-key great-great-great-grandchild)))
    (is (= "L3WAYNAZPxx1fr7KCz7GN9nD5qMBnNiqEJNJMU1z9MMaannAt4aK"
           (privatekey->wif (:private-key great-great-great-grandchild) :mainnet true)))
    (is (= "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
           (:public-key neutered-great-great-great-grandchild)))
    (is (= "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
           (:chain-code great-great-great-grandchild)))
    (is (= "0488b21e0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
           serialized-great-great-great-grandchild-public-key))
    (is (= "0488ade40531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed27100bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
           serialized-great-great-great-grandchild-private-key))))

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

(comment
  (clojure.test/run-all-tests))
