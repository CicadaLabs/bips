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

(ns bips.xmr-utils
  (:require
    [alphabase.base58 :as b58]
    [bips.bip32 :as bip32]
    [bips.bip32-utils :as bip32-utils]
    [bips.bip39 :as bip39]
    [buddy.core.codecs :as codecs]
    [clojure.math.numeric-tower :as math])
  (:import
    org.bouncycastle.jcajce.provider.digest.Keccak$Digest256))

(defn bytes->int
  "Converts a byte array into a big integer.
  It has an optional parameter `little-endian`, which defaults to true.
  If little-endian is true, the byte array is reversed before the conversion"
  [^bytes bytes & {:keys [little-endian]
                   :or {little-endian true}}]
  (let [b (if little-endian (reverse bytes) bytes)]
    (->> b
         (cons (byte 0))
         (byte-array)
         (biginteger))))

(defn- complement-solution
  "Pad leading zeros do a 128 bits number in hexadecimal notation."
  [k]
  (str (apply str (take (- 64 (count k)) (repeat "0"))) k))

(defn sc-reduce32
  "Not every 256-bit integer is a valid EdDSA scalar (private key); it must be less than the ``curve order``.
  `sc_reduce32` is the function to do this.
  2^252 + 27742317777372353535851937790883648493 is the order of Edwards curve 25519. It is also known as the prime l.
  This prime l is chosen such that it is a large prime number and also it is close to 2^252."
  [s]
  (let [n (bytes->int (codecs/hex->bytes s))
        l (biginteger (+ (math/expt 2 252) 27742317777372353535851937790883648493))
        reduced-input (biginteger (.mod n l))
        pre-result (.toByteArray reduced-input)
        result (.toString (bytes->int pre-result) 16)]
    (complement-solution result)))

(defn keccak-256
  "Cryptographic hash function"
  [private-key]
  (let [md (Keccak$Digest256.)
        _ (.update md (codecs/hex->bytes private-key))
        digest (.digest md)]
    (codecs/bytes->hex digest)))

(defn exp-mod
  "Calculates the result of a modular exponentiation of a given base `b`, exponent `e`, and modulus `m`."
  [b e m]
  (if (= e 0)
    (biginteger 1)
    (let [t (atom (.mod  (.pow (exp-mod (biginteger b) (.divide (biginteger e) (biginteger 2)) m) 2) m))]
      (when (not= (.and (biginteger e) (biginteger 1)) 0)
        (reset! t (.mod (.multiply @t (biginteger b)) m)))
      @t)))

;; Prime order (also known as the cofactor) of the Edwards curve 25519
(def q (biginteger (- (math/expt 2 255) 19)))

(defn inv
  "Computes the modular multiplicative inverse of `x` modulo `q`.
  The modular multiplicative inverse of `x` modulo `q` is an integer `y` such that `xy = 1 (mod q)`.
  It does this by using the function `exp-mod` to calculate the result of ``(x^(q-2)) mod q``."
  [x]
  (exp-mod x (.subtract q (biginteger 2)) q))

;; This value is used as the `d` constant in the equation defining the Edwards curve 25519: ``y^2 = x^3 + dx^2y + x``.
(def d (.multiply (biginteger -121665) (inv (biginteger 121666))))

;; Value of the isogeny map from the curve 25519 to the curve 2^255-19, where q is a prime number.
;; The variable is used to map a point on the curve 25519 to a point on the curve 2^255-19, by applying the isogeny to the point.
(def I (exp-mod (biginteger 2) (.divide (.subtract q (biginteger 1)) (biginteger 4)) q))

(defn x-recovery
  "Recover the `x`-coordinate of a point on the Edwards curve 25519, given the `y`-coordinate."
  [y]
  (let [xx (.multiply (.subtract (.pow y 2) (biginteger 1))
                      (inv (.add (reduce (fn [x y] (.multiply x y)) [d y y]) (biginteger 1))))
        x (atom (exp-mod xx (.divide (.add q (biginteger 3)) (biginteger 8)) q))]
    (when (not= (.mod (.subtract (.pow @x 2) xx) q) 0)
      (reset! x (.mod (.multiply @x I) q)))
    (when (not= (.mod @x (biginteger 2)) 0)
      (reset! x (.subtract q @x)))
    @x))

;; `By`, `Bx` and `B` represent a specific point on the curve called the "base point" or "generator point".
;; This point is used as a starting point for performing scalar multiplication on the curve
;; y-coordinate of the base point on the curve.
(def By (.multiply (biginteger 4) (inv (biginteger 5))))

;; x-coordinate of the base point on the curve
(def Bx (biginteger (x-recovery By)))

;; The point `(Bx, By)` is a point on the curve and `B` is a short representation of this point.
(def B [(.mod Bx q) (.mod By q)])

(defn edwards
  [P Q]
  (let [x1 (nth P 0)
        y1 (nth P 1)
        x2 (nth Q 0)
        y2 (nth Q 1)
        x3 (.multiply
             (.add (.multiply x1 y2) (.multiply x2 y1))
             (inv (.add (biginteger 1) (reduce (fn [x y] (.multiply x y)) [d x1 x2 y1 y2]))))
        y3 (.multiply
             (.add (.multiply y1 y2) (.multiply x1 x2))
             (inv (.subtract (biginteger 1) (reduce (fn [x y] (.multiply x y)) [d x1 x2 y1 y2]))))]
    [(.mod x3 q) (.mod y3 q)]))

(defn scalar-multiplication
  "Ed25519 scalarmult function"
  [P e]
  (if (= e 0)
    [(biginteger 0) (biginteger 1)]
    (let [Q (atom (scalar-multiplication P (.divide e (biginteger 2))))]
      (reset! Q (edwards @Q @Q))
      (when (not= (.and e (biginteger 1)) 0)
        (reset! Q (edwards @Q P)))
      @Q)))

(defn encode-point
  "Converts the coordinates of a point on the Edwards curve 25519 represented as a vector of x and y coordinates into a 32-byte string encoded in hexadecimal format."
  [P]
  (let [k (biginteger (nth P 0))
        l (biginteger (nth P 1))
        semi-bits (for [i (range 0 255)]
                    (.and (.shiftRight l (biginteger i)) (biginteger 1)))
        bits (concat semi-bits (list (.and k (biginteger 1)))) ; 0 - 1
        placed-bytes (for [i (range 0 32)] ; 0 - 255
                       (biginteger
                         (reduce (fn [x1 y1] (.add x1 y1))
                                 (for [j (range 0 8)]
                                   (.shiftLeft (biginteger (nth bits (+ (* i 8) j))) j)))))
        pre-result (byte-array placed-bytes)]
    (codecs/bytes->hex pre-result)))

(defn ->public-key
  "Compute public counterparts of private view and spend key"
  [private-key]
  (let [private-key-byte-array (codecs/hex->bytes private-key)
        a (biginteger (bytes->int private-key-byte-array))
        A (scalar-multiplication B a)]
    (encode-point A)))

(defn pad-leading-ones
  "Pad `x` with `1`s (1 is 0 in Base58) if it has less than `n` characters."
  [n x]
  (if (< (count x) n)
    (str (apply str (take (- n (count x)) (repeat "1"))) x)
    x))

(defn get-primary-public-address
  "Create the actual Public Address from `public-spend-key` and `public-view-key`"
  [public-spend-key
   public-view-key]
  (let [raw-public-address (str "12" public-spend-key public-view-key)
        raw-public-address-hash (keccak-256 raw-public-address)
        public-address (str raw-public-address
                            (apply str (take 8 raw-public-address-hash)))]
    (loop [K public-address
           res ""]
      (if (> (count K) 10)
        (recur (apply str
                      (take-last
                        (- (count K) 16) K))
               (str res (pad-leading-ones 11
                                          (b58/encode
                                            (codecs/hex->bytes
                                              (apply str (take 16 K)))))))
        (str res (pad-leading-ones 7 (b58/encode (codecs/hex->bytes K))))))))

(defn ->hexadecimal-seed
  "Formats a private key to the hexadecimal seed with sc-reduce."
  [private-key]
  (sc-reduce32 private-key))

(defn derive-from-mnemonic
  "Derive from a BIP039 mnemonic seed to a spend key for Monero."
  ([mnemonic path key-type]
   (-> (bip39/mnemonic->seed mnemonic)
       (bip32/derive-path path key-type)
       (:private-key)
       (sc-reduce32)))

  ([{:keys [mnemonic path key-type]}]
   (derive-from-mnemonic mnemonic path key-type)))

(defn ->private-view-key
  "Derives a private view key from a private spend key."
  [private-spend-key]
  (-> private-spend-key
      (keccak-256)
      (sc-reduce32)))
