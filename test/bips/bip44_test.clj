(ns bips.bip44-test
  (:require
    [bips.bip44 :as sut]
    [clojure.test :as t]))

;; https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#examples
(t/deftest derivation-path-tests
  (t/is (= "m/44'/0'/0'/0/0"
           (sut/derivation-path "BTC" 0 :external 0)))
  (t/is (= "m/44'/0'/0'/0/1"
           (sut/derivation-path "BTC" 0 :external 1)))
  (t/is (= "m/44'/0'/0'/1/0"
           (sut/derivation-path "BTC" 0 :change 0)))
  (t/is (= "m/44'/0'/0'/1/1"
           (sut/derivation-path "BTC" 0 :change 1)))
  (t/is (= "m/44'/0'/1'/0/0"
           (sut/derivation-path "BTC" 1 :external 0)))
  (t/is (= "m/44'/0'/1'/0/1"
           (sut/derivation-path "BTC" 1 :external 1)))
  (t/is (= "m/44'/0'/1'/1/0"
           (sut/derivation-path "BTC" 1 :change 0)))
  (t/is (= "m/44'/0'/1'/1/1"
           (sut/derivation-path "BTC" 1 :change 1))))
