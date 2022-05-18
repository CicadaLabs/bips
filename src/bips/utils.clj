(ns cicadabank.proposals.utils
  (:require
    [clj-commons.digest :as digest]
    [clojure.string :as str]))

(def bip39-dictionary
  "BIP-39 English dictionary"
  (-> "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
      slurp
      (str/split #"\n")))

(defn index-of
  "Return the index of word in the BIP-39 English dictionary"
  [word] (count (take-while (partial not= word) bip39-dictionary)))

(defn seed-phrase->binary-array
  "Turn a seed phrase into a binary array of ``0`` and ``1``"
  [seed-phrase]
  (str/split (reduce #(str %1 %2)
                     (map #(format "%011d" (Long/parseLong (Integer/toBinaryString %)))
                          (map #(index-of %) (str/split seed-phrase #" "))))
             #""))

(defn binary-array->byte-array
  "Turn a binary array of 0 and 1 into a byte array"
  [binary-array size]
  (byte-array (map #(Integer/parseInt % 2)
                   (map (fn [a] (reduce #(str %1 %2) a))
                        (partition 8
                                   (byte-array  (map #(Integer/parseInt %)
                                                     (take size binary-array))))))))

(defn entropy-string->entropy-byte-array
  "Turn an entropy string into entropy byte array"
  [entropy-string]
  (->> entropy-string
       (#(clojure.string/split % #""))
       (partition 2)
       (map (fn [a] (reduce #(str %1 %2) a)))
       (map #(Integer/parseInt % 16))))

(defn seed-phrase->entropy
  "Turn a seed phrase into an intropy byte array"
  [seed-phrase]
  (map #(format "%x" %)
       (binary-array->byte-array (seed-phrase->binary-array seed-phrase)
                                 (-> seed-phrase
                                     (#(str/split % #" "))
                                     count
                                     (#(* % 11))))))

(defn entropy->binary
  "Turn an entropy byte array into a binary array of 0 and 1"
  [entropy]
  (map #(Integer/parseInt %) (clojure.string/split
                               (reduce #(str %1 %2) (map #(format "%08d" (Integer/parseInt (Integer/toBinaryString %)))
                                                         entropy)) #"")))

(defn binary->byte-binary
  "Turn a binary array into a byte array"
  [binary]
  (map (fn [a] (reduce #(str %1 %2) a)) (partition 8 binary)))

(defn random-bits
  "Return a random array of bits of size `size`"
  [size]
  (byte-array (repeatedly size #(byte (rand-int 2)))))

(defn byte-binary->byte-array
  "Turn a binary array into a byte array"
  [byte-binary]
  (map #(Integer/parseInt % 2) byte-binary))

(defn byte-array->digest
  "Compute the digest of a byte array"
  [binary-array]
  (->> binary-array
       (partition 8)
       (map #(reduce str %))
       (map #(Integer/parseInt % 2))
       byte-array
       digest/sha256
       (#(str/split % #""))
       (partition 2)
       (map #(reduce str %))
       (map #(Integer/parseInt % 16))))

(defn size->suffix-length
  "Return the suffix length from the size"
  [size]
  (let [entropies [128 160 192 224 256]
        suffix-length (map #(/ % 32) entropies)]
    (nth suffix-length (.indexOf entropies size))))

(defn checksum
  "Compute the checksum of a seed phrase from the size and the digest"
  [size digest]
  (let [hash-suffix (clojure.string/split (apply str (take (size->suffix-length size) (format "%08d" (Integer/parseInt (Integer/toBinaryString (first digest)))))) #"")]
    hash-suffix))

(defn binary+checksun->seed-phrase-binary
  "Turn a random binary data and its checksum into seed phrase in binary form"
  [binary checksum suffix-length]
  (concat binary
          (map #(Integer/parseInt %) (take suffix-length checksum))))

(defn binary-with-digest->seed-phrase
  "Turn a seed phrase and its digest in binary form into seed phrase"
  [binary-with-digest]
  (let [seed-phrase-binary (map (fn [a] (reduce #(str %1 %2) a)) (partition 11 binary-with-digest))
        seed-phrase-dec (map #(Long/parseLong % 2) seed-phrase-binary)
        seed-phrase (reduce #(str %1 " " %2) (map #(nth bip39-dictionary %) seed-phrase-dec))]
    seed-phrase))
