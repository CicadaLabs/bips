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

(ns bips.xmr-utils-test
  (:require
    [bips.xmr-utils :as sut]
    [clojure.test :as t]))

;; test vector from
;; https://github.com/smessmer/crypto-wallet-gen#2-generate-a-monero-wallet-with-the-same-seed-phrase
(t/deftest test-vector-1
  (let [mnemonic-seed "acid employ suggest menu desert pioneer hard salmon consider stuff margin over bus fiction direct useful tornado output forward wing cute chicken ladder hockey"
        private-spend-key (sut/derive-from-mnemonic mnemonic-seed "m/44H/128H/0H" :private)
        private-view-key (sut/->private-view-key private-spend-key)
        primary-address (sut/get-primary-public-address
                          (sut/->public-key private-spend-key)
                          (sut/->public-key private-view-key))]
    (t/is (= "4d93d393f0f2c4a9837524f9d740fa85af54c464864aa8c16d39ef3409781802"
             private-spend-key))
    (t/is (= "c2e6e8597bb5050e57a98d284faf27edc3587d57cccd8a2b3edfd38cdd23af0b"
             private-view-key))
    (t/is (= "4295Lfg8n2pJiN5eC6YHMGGR4oZ1PuaGJNyNo24wNjrdNPLBSVFFHVEay83fFwJBCWPVumE8xW6wKB6Udj8ttmZoNLDTgsn"
             primary-address))))

;; test vector from https://github.com/skaht/XMR
(t/deftest test-vector-2
  (let [seed "f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11"
        private-spend-key (sut/->hexadecimal-seed seed)
        private-view-key (sut/->private-view-key private-spend-key)
        public-spend-key (sut/->public-key private-spend-key)
        public-view-key (sut/->public-key private-view-key)
        primary-address (sut/get-primary-public-address
                          public-spend-key public-view-key)]
    (t/is (= "0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01"
             private-spend-key))
    (t/is (= "f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805"
             private-view-key))
    (t/is (= "2794fe656a521e21e4135aa13381b42cbeb180e653deda210f2039ca1009d110"
             public-spend-key))
    (t/is (= "d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125"
             public-view-key))
    (t/is (= "4387BkqvmwB6fnVf4kwNUb8V5jJbQtWNV6XiSiSw1kXz3pPAy9ooZe6FsqKYLo4b19YzoCJQPxWdy9j9kStsRLLg5B8R4Ke"
             primary-address))
    (t/is (= "0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01"
             (sut/sc-reduce32 "f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11")))
    (t/is (= "fcc659eca955591729400f38c6917e8ae0af1405b2a03b5a7074a74b0946a8d5"
             (sut/keccak-256 "0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01")))
    (t/is (= "f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805"
             (sut/sc-reduce32 "fcc659eca955591729400f38c6917e8ae0af1405b2a03b5a7074a74b0946a8d5")))
    (t/is (= "d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125"
             (sut/->public-key "f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805")))))

(comment
  (t/run-all-tests))
