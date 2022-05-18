(ns cicadabank.proposals.bip39
  (:require
    [cicadabank.proposals.utils :refer :all]
    [clojure.string :as str]))

(defn random-binary->seed-phrase [random-binary]
  (let [entropies [128 160 192 224 256]
        seed-phrase-length (map #(int (Math/ceil (/ % 11))) entropies)
        size (count random-binary)
        _ (when (not (.contains entropies size)) (throw (Exception. "Invalid entropy.")))
        seed-phrase (binary-with-digest->seed-phrase
                      (binary+checksun->seed-phrase-binary random-binary
                                                           (checksum size (byte-array->digest random-binary))
                                                           (size->suffix-length size)))]
    (assert (= (.length (str/split seed-phrase #" ")) (nth seed-phrase-length (.indexOf entropies size))))
    seed-phrase))
