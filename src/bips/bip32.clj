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

(ns bips.bip32
  (:require
    [bips.bip32-utils :refer [add-point
                              compress-public-key
                              group-add
                              CURVE_PARAMS
                              decompressKey
                              hardened hardened?
                              ->32-bytes ->33-bytes
                              private->public-key]]
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]
    [clojure.string :as str])
  (:import
    java.math.BigInteger))

(defn derive-master-node
  "Master key generation
  Reference: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation`"
  [seed]
  (let [master-code
        (codecs/bytes->hex
          (mac/hash (codecs/hex->bytes seed) {:key (codecs/str->bytes "Bitcoin seed")
                                              :alg :hmac+sha512}))
        private-key (apply str (take 64 master-code))]
    (when (or (= 0 (.compareTo (BigInteger/ZERO) (BigInteger. private-key 16)))
              (>= (.compareTo (BigInteger. private-key 16)
                              (.getN CURVE_PARAMS)) 0))
      (throw (Exception. "the master key is invalid.")))
    {:private-key (->32-bytes private-key)
     :public-key (compress-public-key (.toString (private->public-key
                                                   (BigInteger. private-key 16)) 16))
     :chain-code (apply str (take-last 64 master-code))
     :depth 0}))

(defn CKDpriv
  "Private parent key → private child key
  Reference: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key`"
  [{k-par :private-key
    c-par :chain-code
    depth :depth} index]
  (let [K-par (compress-public-key
                (.toString (private->public-key
                             (BigInteger. (apply str k-par)
                                          16))
                           16))
        I (if (>= index (hardened 0))
            (mac/hash (codecs/hex->bytes (str (->33-bytes k-par)
                                              (format "%08x" index)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512})
            (mac/hash (codecs/hex->bytes (str K-par
                                              (format "%08x" index)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512}))
        IL (byte-array (take 32 I))
        IR (byte-array (take-last 32 I))
        ki (group-add k-par IL)]
    (when (or (>= (.compareTo (BigInteger. 1 IL) (.getN CURVE_PARAMS)) 0)
              (= 0 (.compareTo BigInteger/ZERO ki)))
      (throw (Exception. "key is invalid, proceed with the next value for i.")))
    {:private-key (->32-bytes (.toString ki 16))
     :chain-code (codecs/bytes->hex IR)
     :index index
     :depth (+ depth 1)}))

(defn CKDpub
  "Public parent key → public child key
  Reference: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key`"
  [{K-par :public-key
    c-par :chain-code
    depth :depth} index]
  (if (>= index (hardened 0))
    (throw (Exception. "Cannot derive a public key for hardened child keys."))
    (let [I (mac/hash (codecs/hex->bytes (str K-par
                                              (format "%08x" index)))
                      {:key (codecs/hex->bytes c-par)
                       :alg :hmac+sha512})
          IL (byte-array (take 32 I))
          _ (when (>= (.compareTo (BigInteger. 1 IL) (.getN CURVE_PARAMS)) 0)
              (throw (Exception. "key is invalid, proceed with the next value for i.")))
          public-key (add-point K-par IL)]
      (when (.equals public-key
                     (.getInfinity (.getCurve CURVE_PARAMS)))
        (throw (Exception. "key is invalid, proceed with the next value for i.")))
      {:public-key (codecs/bytes->hex (byte-array
                                        (take-last 64
                                                   (.getEncoded public-key true))))
       :chain-code (codecs/bytes->hex (byte-array (take-last 32 I)))
       :index index
       :depth (+ depth 1)})))

(defn N
  "Private parent key → public child key
  Reference: `https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--public-child-key`"
  [{k-par :private-key
    c-par :chain-code
    index :index
    depth :depth}]
  {:public-key (compress-public-key
                 (.toString
                   (private->public-key
                     (BigInteger. k-par 16)) 16))
   :chain-code c-par
   :index index
   :depth depth})

(defmacro derive-path
  "Derive a public/private key from a seed and a derivation path.
  e.g. (derive-path \"000102030405060708090a0b0c0d0e0f\" \"m/0H/1/2H/2/1000000000\" :private) → `{:private-key
  \"471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8\",
  :chain-code
  \"c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e\",
  :index 1000000000,
  :depth 5}`"
  [seed chain-path key-type]
  (let [path-parts (gensym 'path-parts)
        part (gensym 'part)
        parts (gensym 'parts)
        current-node (gensym 'current-node)
        index (gensym 'index)]
       `(let [~path-parts (str/split ~chain-path #"/")]
          (loop [~current-node (if (= "m" (first ~path-parts))
                                 (derive-master-node ~seed)
                                 (throw (Exception.
                                         (str "Invalid path: " (first ~path-parts)))))
                 ~parts (rest ~path-parts)]
            (if (seq ~parts)
              (let [~part (first ~parts)
                    ~index (if (hardened? ~part)
                             (hardened (Integer/parseInt (subs ~part 0 (- (count ~part) 1))))
                             (Integer/parseInt ~part))]
                (recur
                 (CKDpriv ~current-node ~index)
                 (rest ~parts)))
              (if (= :public ~key-type)
                (N ~current-node)
                ~current-node))))))
