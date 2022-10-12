(ns bips.bip32-utils
  (:require
    [alphabase.base58 :as b58]
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash]
    [clojure.math.numeric-tower :as math])
  (:import
    (org.bouncycastle.asn1.x9
      X9IntegerConverter)
    (org.bouncycastle.crypto.digests
      RIPEMD160Digest)
    (org.bouncycastle.crypto.ec
      CustomNamedCurves)
    (org.bouncycastle.crypto.params
      ECDomainParameters)
    (org.bouncycastle.math.ec
      FixedPointCombMultiplier)))

(def CURVE_PARAMS (CustomNamedCurves/getByName "secp256k1"))

(def CURVE
  (new ECDomainParameters
       (.getCurve CURVE_PARAMS)
       (.getG CURVE_PARAMS)
       (.getN CURVE_PARAMS)
       (.getH CURVE_PARAMS)))

(def version-bytes
  {:mainnet {:public "0488b21e"
             :private "0488ade4"}
   :testnet {:public "043587cf"
             :private "04358394"}})

(defn sha256hash160 [input]
  (let [sha256 (hash/sha256 input)
        digest (new RIPEMD160Digest)
        output (byte-array 20)]
    (.update digest sha256 0 (count sha256))
    (.doFinal digest output 0)
    output))

(defn compress-public-key [K]
  (str (if (= 0 (mod (nth (codecs/hex->bytes K) 63) 2))
         "02"
         "03")
       (apply str (take 64 K))))

(defn private-key->32-bytes [k]
  (str (apply str (take (- 64 (count k)) (repeat "0"))) k))

(defn private-key->33-bytes [k]
  (str (apply str (take (- 66 (count k)) (repeat "0"))) k))

(defn decompressKey [xBN yBit]
  (let [x9 (new X9IntegerConverter)
        compEnc (.integerToBytes x9 xBN (+ 1 (.getByteLength x9 (.getCurve CURVE))))]
    (aset-byte compEnc 0 (if yBit
                           0x02
                           0x03))
    (.decodePoint (.getCurve CURVE) compEnc)))

(defn serialize [network type depth fingerprint child-number chain-code key-data]
  (str (get-in version-bytes [network type])
       (format "%02x" depth)
       (format "%08x" fingerprint)
       (format "%08x" child-number)
       chain-code
       (if (= :public type)
         key-data
         (private-key->33-bytes key-data))))

(defn serialize-base58 [network type depth fingerprint
                        child-number chain-code key-data]
  (let [encoded-key (str (get-in version-bytes [network type])
                         (format "%02x" depth)
                         (format "%08x" fingerprint)
                         (format "%08x" child-number)
                         chain-code
                         (if (= :public type)
                           key-data
                           (private-key->33-bytes key-data)))
        key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                   (byte-array (codecs/hex->bytes encoded-key)))))]
    (b58/encode (codecs/hex->bytes (str encoded-key
                                        (apply str (take 8 key-hash)))))))

(defn encode-base58 [master-key]
  (let [key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256 master-key)))]
    (b58/encode (codecs/hex->bytes (str (codecs/bytes->hex master-key)
                                        (apply str (take 8 key-hash)))))))

(defn deserialize-base58 [encoded-key]
  (let [decoded-key (b58/decode encoded-key)
        _ (when (> (count decoded-key) 82)
            (throw (Exception. "Found unexpected data in key")))
        version (codecs/bytes->hex
                  (byte-array (take 4 decoded-key)))
        network (case version
                  "0488b21e"
                  :mainnet
                  "0488ade4"
                  :mainnet
                  "043587cf"
                  :testnet
                  "04358394"
                  :testnet
                  (throw (Exception. (format "unknown extended key version: %s"
                                             version))))
        type (case version
               "0488b21e"
               :public
               "0488ade4"
               :private
               "043587cf"
               :public
               "04358394"
               :private
               (throw (Exception. (format "unknown extended key version: %s"
                                          version))))
        depth (Integer/parseInt
                (codecs/bytes->hex
                  (byte-array
                    (take 1 (take-last 78 decoded-key)))) 16)
        fingerprint (Long/parseLong
                      (codecs/bytes->hex
                        (byte-array
                          (take 4 (take-last 77 decoded-key)))) 16)
        index (Long/parseLong
                (codecs/bytes->hex
                  (byte-array
                    (take 4 (take-last 73 decoded-key)))) 16)
        chain-code (codecs/bytes->hex
                     (byte-array
                       (take 32 (take-last 69 decoded-key))))
        key-data (codecs/bytes->hex
                   (byte-array
                     (take 33 (take-last 37 decoded-key))))
        key-hash (codecs/bytes->hex
                   (byte-array
                     (take-last 4 decoded-key)))]
    (when (and (= :public type)
               (= "00" (apply str (take 2 key-data))))
      (throw (Exception. "pubkey version / prvkey mismatch")))
    (when (and (= :private type)
               (or (= "02" (apply str (take 2 key-data)))
                   (= "03" (apply str (take 2 key-data)))))
      (throw (Exception. "prvkey version / pubkey mismatch")))
    (when (and (= :public type)
               (not (or (= "02" (apply str (take 2 key-data)))
                        (= "03" (apply str (take 2 key-data))))))
      (throw (Exception. (format "invalid pubkey prefix: %s"
                                 (apply str (take 2 key-data))))))
    (when (and (= :private type)
               (not (= "00" (apply str (take 2 key-data)))))
      (throw (Exception. (format "invalid prvkey prefix: %s"
                                 (apply str (take 2 key-data))))))
    (when (and (= 0 depth)
               (not (= 0 fingerprint)))
      (throw (Exception. (format "zero depth with non-zero parent fingerprint: %s"
                                 fingerprint))))
    (when (and (= 0 depth)
               (not (= 0 index)))
      (throw (Exception. (format "zero depth with non-zero index: %s"
                                 index))))
    (when (= :public type)
      (try (decompressKey
             (BigInteger. (apply str (take-last 64 key-data)) 16)
             (= 2 (Integer/parseInt (apply str (take 2 key-data)))))
           (catch IllegalArgumentException _
             (throw (Exception. (format "invalid pubkey: %s" key-data))))))
    (when (and (= :private type)
               (or
                 (= -1 (.compareTo (BigInteger. key-data 16)
                                   (BigInteger/ONE)))
                 (= 1 (.compareTo (BigInteger. key-data 16)
                                  (.subtract
                                    (.getN CURVE_PARAMS)
                                    (BigInteger/ONE))))))
      (throw (Exception. (format "private key %s not in 1..n-1" key-data))))
    (when (not (= key-hash
                  (apply str
                         (take 8
                               (codecs/bytes->hex
                                 (hash/sha256
                                   (hash/sha256 (byte-array (take 78 decoded-key)))))))))
      (throw (Exception. (format "invalid checksum: %s" key-hash))))
    {:network network
     :type type
     :depth depth
     :index index
     :fingerprint fingerprint
     :chain-code chain-code
     :public-key (case type
                   :public
                   key-data
                   nil)
     :private-key (case type
                    :private
                    key-data
                    nil)}))

(defn key-identifier [K]
  (sha256hash160 (codecs/hex->bytes K)))

(defn key-fingerprint [K]
  (let [identifier (key-identifier K)]
    (bit-or (bit-and (nth identifier 3) 0xFF)
            (bit-shift-left (bit-and (nth identifier 2) 0xFF) 8)
            (bit-shift-left (bit-and (nth identifier 1) 0xFF) 16)
            (bit-shift-left (bit-and (first identifier) 0xFF) 24))))

(defn hardened [index]
  (+ (math/expt 2 31) index))

(defn hardened? [path-part]
  (= \H (last (char-array path-part))))

(defn private->public-point [privKey]
  (if (> (.bitLength privKey) (.bitLength (.getN CURVE)))
    (.multiply (FixedPointCombMultiplier.) (.getG CURVE) (.mod privKey (.getN CURVE)))
    (.multiply (FixedPointCombMultiplier.) (.getG CURVE) privKey)))

(defn private->public-key [privKey]
  (let [point (private->public-point privKey)
        encoded (.getEncoded point false)]
    (BigInteger. 1 (byte-array (take-last (- (count encoded) 1) encoded)))))

(defn group-add [k-par IL]
  (.mod (.add (BigInteger. k-par 16)
              (BigInteger. 1 IL))
        (.getN CURVE_PARAMS)))

(defn add-point [Ki IL]
  (.add
    (private->public-point (BigInteger. 1 IL))
    (decompressKey (BigInteger. (apply str Ki) 16)
                   (= 0 (mod (nth (codecs/hex->bytes Ki) 0) 2)))))
