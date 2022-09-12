(ns cicadabank.proposals.utils
  (:require
    [clj-commons.digest :as digest]
    [clojure.set]
    [clojure.string :as str])
  (:import
    java.security.SecureRandom
    org.bouncycastle.crypto.prng.BasicEntropySourceProvider))

(def languages
  ["chinese_simplified" "chinese_traditional" "czech" "english"
   "french" "italian" "japanese" "portuguese" "spanish"])

(defn bip39-dictionary
  "Return the BIP-39 dictionary for the provided `language`.
  If the language is not available, an exception is thrown."
  [language]
  (when (not (.contains languages language))
    (throw (Exception. "Languaged not supported.")))
  (-> (str "resources/assets/bip-39/" language ".txt")
      slurp
      (str/split #"\n")))

(defn index-of
  "Return the index of word in the BIP-39 English dictionary"
  [word language] (count (take-while (partial not= word) (bip39-dictionary language))))

(defn seed-phrase->binary-array
  "Turn a seed phrase into a binary array of ``0`` and ``1``"
  [seed-phrase language]
  (str/split (apply str
                    (map #(format "%011d" (Long/parseLong (Integer/toBinaryString %)))
                         (map #(index-of % language) (str/split seed-phrase #" "))))
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
       (map #(apply str %))
       (map #(Integer/parseInt % 16))))

(defn seed-phrase->entropy
  "Turn a seed phrase into an intropy byte array"
  [seed-phrase language]
  (map #(format "%x" %)
       (binary-array->byte-array (seed-phrase->binary-array seed-phrase language)
                                 (-> seed-phrase
                                     (#(str/split % #" "))
                                     count
                                     (#(* % 11))))))

(defn entropy->binary
  "Turn an entropy byte array into a binary array of 0 and 1"
  [entropy]
  (->> entropy
       (map #(format "%08d"
                     (Integer/parseInt
                      (apply str
                             (take-last 8
                                        (Integer/toBinaryString %))))))
       (apply str)
       (#(str/split % #""))
       (map #(Integer/parseInt %))))

(defn binary->byte-binary
  "Turn a binary array into a byte array"
  [binary]
  (map #(apply str %) (partition 8 binary)))

(defn random-entropy
  "Return a random array of bytes of `size` bits"
  [size]
  (let [random (SecureRandom.)
        provider (BasicEntropySourceProvider. random true)]
    (-> provider
        (.get size)
        (.getEntropy))))

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
  (let [entropy-sizes [128 160 192 224 256]
        suffix-length (map #(/ % 32) entropy-sizes)]
    (nth suffix-length (.indexOf entropy-sizes size))))

(defn checksum
  "Compute the checksum of a seed phrase from the size and the digest"
  [size digest]
  (clojure.string/split
    (->> digest
         first
         Integer/toBinaryString
         Integer/parseInt
         (format "%08d")
         (take (size->suffix-length size))
         (apply str))
    #""))

(defn binary+checksun->seed-phrase-binary
  "Turn a random binary data and its checksum into seed phrase in binary form"
  [binary checksum suffix-length]
  (concat binary
          (map #(Integer/parseInt %) (take suffix-length checksum))))

(defn binary-with-digest->seed-phrase
  "Turn a seed phrase and its digest in binary form into seed phrase"
  [binary-with-digest language]
  (let [seed-phrase-binary (map #(apply str %) (partition 11 binary-with-digest))
        seed-phrase-dec (map #(Long/parseLong % 2) seed-phrase-binary)
        seed-phrase (str/join (case language
                                "japanese" "\u3000"
                                " ")
                              (map #(nth (bip39-dictionary language) %) seed-phrase-dec))]
    seed-phrase))

(defn detect-language
  "Detect the language of a mnemonic.
  If no language is detected or if there is any ambiguity, an exception is thrown."
  [mnemonic]
  (let [words (str/split mnemonic (if (.contains mnemonic "\u3000")
                                    #"\u3000"
                                    #" "))
        possible (loop [langs languages
                        v '()]
                   (if (seq langs)
                     (if (= (count (set words))
                            (count (clojure.set/intersection
                                     (set words)
                                     (set (bip39-dictionary (first langs))))))
                       (recur (rest langs)
                              (conj v (first langs)))
                       (recur (rest langs)
                              v))
                     v))]
    (when (empty? possible)
      (throw (Exception. "Language not detected.")))
    (if (= 1 (count possible))
      (first possible)
      (throw (Exception. (str "Language ambigous between "
                              (str/join ", " possible)))))))
