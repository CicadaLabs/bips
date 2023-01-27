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
           (sut/derivation-path "BTC" 1 :change 1)))
  (t/is (= "m/44H/0H/0H/0/0"
           (sut/derivation-path "BTC" 0 :external 0 "H")))
  (t/is (= "m/44H/0H/0H/0/1"
           (sut/derivation-path "BTC" 0 :external 1 "H")))
  (t/is (= "m/44H/0H/0H/1/0"
           (sut/derivation-path "BTC" 0 :change 0 "H")))
  (t/is (= "m/44H/0H/0H/1/1"
           (sut/derivation-path "BTC" 0 :change 1 "H")))
  (t/is (= "m/44H/0H/1H/0/0"
           (sut/derivation-path "BTC" 1 :external 0 "H")))
  (t/is (= "m/44H/0H/1H/0/1"
           (sut/derivation-path "BTC" 1 :external 1 "H")))
  (t/is (= "m/44H/0H/1H/1/0"
           (sut/derivation-path "BTC" 1 :change 0 "H")))
  (t/is (= "m/44H/0H/1H/1/1"
           (sut/derivation-path "BTC" 1 :change 1 "H"))))

(t/deftest derivation-path-account-tests
  (t/is (= "m/44'/0'/0'"
           (sut/derivation-path "BTC" 0)))
  (t/is (= "m/44'/128'/0'"
           (sut/derivation-path "XMR" 0)))
  (t/is (= "m/44H/0H/0H"
           (sut/derivation-path "BTC" 0 "H")))
  (t/is (= "m/44H/128H/0H"
           (sut/derivation-path "XMR" 0 "H"))))

(t/deftest exeptional-case
  (t/is (thrown-with-msg? Exception #"Coin type .* not found in coin_types.edn file."
          (sut/derivation-path "WTV" 1 :change 1))))

(comment
  (clojure.test/run-all-tests))
