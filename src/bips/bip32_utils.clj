(ns bips.bip32-utils
  (:require
    [buddy.core.codecs :as codecs]
    [buddy.core.hash :as hash])
  (:import
    (org.bitcoinj.core
      Base58
      Utils)
    (org.bouncycastle.asn1.x9
      X9IntegerConverter)
    (org.bouncycastle.crypto.ec
      CustomNamedCurves)
    (org.bouncycastle.crypto.params
      ECDomainParameters)))

(def CURVE_PARAMS (CustomNamedCurves/getByName "secp256k1"))

(def CURVE
  (new ECDomainParameters
       (.getCurve CURVE_PARAMS)
       (.getG CURVE_PARAMS)
       (.getN CURVE_PARAMS)
       (.getH CURVE_PARAMS)))

(def version-bytes
  {:mainnet {:public "0488B21E"
             :private "0488ADE4"}
   :testnet {:public "043587CF"
             :private "04358394"}})

(defn compress-public-key [K]
  (str (if (= 0 (mod (nth K 63) 2))
         "02"
         "03")
       (apply str (take 64 (codecs/bytes->hex K)))))

(defn private-key-to-33-bytes [k]
  (str "00" k))

(defn serialize [network type depth fingerprint
                 child-number chain-code key-data]
  (let [encoded-key (str (get (get version-bytes network) type)
                         (format "%02x" depth)
                         (format "%08x" fingerprint)
                         (format "%08x" child-number)
                         chain-code
                         (if (= :public type)
                           (compress-public-key key-data)
                           (private-key-to-33-bytes key-data)))
        key-hash (codecs/bytes->hex (hash/sha256 (hash/sha256
                                                   (byte-array (codecs/hex->bytes encoded-key)))))]
    (Base58/encode (codecs/hex->bytes (str encoded-key
                                           (apply str (take 8 key-hash)))))))

(defn key-identifier [K]
  (Utils/sha256hash160 (codecs/hex->bytes (compress-public-key K))))

(defn key-fingerprint [K]
  (let [identifier (key-identifier K)]
    (bit-or (bit-and (nth identifier 3) 0xFF)
            (bit-shift-left (bit-and (nth identifier 2) 0xFF) 8)
            (bit-shift-left (bit-and (nth identifier 1) 0xFF) 16)
            (bit-shift-left (bit-and (first identifier) 0xFF) 24))))

(defn decompressKey [xBN yBit]
  (let [x9 (new X9IntegerConverter)
        compEnc (.integerToBytes x9 xBN (+ 1 (.getByteLength x9 (.getCurve CURVE))))]
    (aset-byte compEnc 0 (if yBit
                           0x02
                           0x03))
    (.decodePoint (.getCurve CURVE) compEnc)))
