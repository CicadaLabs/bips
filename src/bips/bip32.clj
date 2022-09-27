(ns bips.bip32
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.mac :as mac]
    [bips.bip32-utils :refer [add-point
                              compress-public-key
                              group-add
                              CURVE_PARAMS
                              decompressKey
                              hardened hardened?
                              private-key->33-bytes
                              private->public-key]]
    [clojure.string :as str])
  (:import
    java.math.BigInteger))

(defn derive-master-node
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
    {:private-key private-key
     :public-key (compress-public-key (.toString (private->public-key
                                                   (BigInteger. private-key 16)) 16))
     :chain-code (apply str (take-last 64 master-code))
     :depth 0}))

(defn CKDpriv [{k-par :private-key
                c-par :chain-code
                depth :depth} index]
  (let [K-par (compress-public-key
                (.toString (private->public-key
                             (BigInteger. (apply str k-par)
                                          16))
                           16))
        I (if (>= index (hardened 0))
            (mac/hash (codecs/hex->bytes (str (private-key->33-bytes k-par)
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
    {:private-key (.toString ki 16)
     :chain-code (codecs/bytes->hex IR)
     :index index
     :depth (+ depth 1)}))

(defn CKDpub [{K-par :public-key
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

(defn N [{k-par :private-key
          c-par :chain-code
          index :index
          depth :depth}]
  {:public-key (compress-public-key
                 (.toString
                   (private->public-key
                     (BigInteger. (apply str k-par) 16)) 16))
   :chain-code c-par
   :index index
   :depth depth})

(defmacro derive-path [seed chain-path key-type]
  (let [path-parts (str/split chain-path #"/")]
    (loop [current-node (if (= "m" (first path-parts))
                          `(derive-master-node ~seed)
                          (throw (Exception.
                                   (str "Invalid path: " (first path-parts)))))
           parts (rest path-parts)]
      (if (seq parts)
        (let [part (first parts)
              index (if (hardened? part)
                      (hardened (Integer/parseInt (subs part 0 (- (count part) 1))))
                      (Integer/parseInt part))]
          (recur
            `(CKDpriv ~current-node ~index)
            (rest parts)))
        (if (= :public key-type)
          `(N ~current-node)
          current-node)))))

