(ns cicadabank.proposals.bip39
  (:import
    org.apache.commons.codec.digest.DigestUtils))

(def bip39-dictionary
  (-> "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
      slurp
      (clojure.string/split #"\n")))

(defn generate-seed-phrase [size]
  (let [entropies [128 160 192 224 256]
        _ (when (not (.contains entropies size)) (throw (Exception. "Invalid entropy.")))
        seed-phrase-length (map #(int (Math/ceil (/ % 11))) entropies)
        random-bits (byte-array (repeatedly size #(byte (rand-int 2))))
        random-bytes-binary (map (fn [a] (reduce #(str %1 %2) a)) (partition 4 random-bits))
        random-bytes (map #(Byte/parseByte % 2) random-bytes-binary)
        digest (DigestUtils/sha256 (byte-array random-bytes))
        suffix-length (map #(/ % 32) entropies)
        digest-part (byte-array (take (Math/ceil (/ (nth suffix-length (.indexOf entropies size) entropies) 4)) digest))
        hash-suffix (clojure.string/split (format "%08d" (Long/parseLong (apply str (take-last 8 (Integer/toBinaryString (aget digest-part 0)))))) #"")
        _ (clojure.pprint/pprint hash-suffix)
        rand-bits-with-digest (concat random-bits
                                      (map #(Integer/parseInt %) (take (nth suffix-length (.indexOf entropies size)) hash-suffix)))
        seed-phrase-binary (map (fn [a] (reduce #(str %1 %2) a)) (partition 11 rand-bits-with-digest))
        seed-phrase-dec (map #(Long/parseLong % 2) seed-phrase-binary)
        seed-phrase (reduce #(str %1 " " %2) (map #(nth bip39-dictionary %) seed-phrase-dec))]
    (assert (= (.length (clojure.string/split seed-phrase #" ")) (nth seed-phrase-length (.indexOf entropies size))))
    seed-phrase))
