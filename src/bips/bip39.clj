(ns bips.bip39
  (:require
    [bips.utils :refer :all]
    [buddy.core.codecs :as codecs]
    [clojure.string :as str])
  (:import
    java.nio.charset.StandardCharsets
    java.text.Normalizer
    javax.crypto.SecretKeyFactory
    javax.crypto.spec.PBEKeySpec
    org.apache.commons.lang3.StringUtils))

(defn entropy->mnemonic
  "Generate the mnemonic from entropy in binary format.
  Entropy size has to be a multiple of 32 in the range 128-256 bits."
  ([entropy]
   (entropy->mnemonic entropy "english"))
  ([entropy language]
   (let [entropy-sizes [128 160 192 224 256]
         seed-phrase-length (map #(int (Math/ceil (/ % 11))) entropy-sizes)
         entropy-binary (entropy->binary entropy)
         size (count entropy-binary)
         _ (when (not (.contains entropy-sizes size)) (throw (Exception. "Invalid entropy.")))
         seed-phrase (binary-with-digest->seed-phrase
                       (binary+checksun->seed-phrase-binary entropy-binary
                                                            (checksum size (byte-array->digest entropy-binary))
                                                            (size->suffix-length size))
                       language)]
     (assert (= (.length (str/split seed-phrase (case language
                                                  "japanese" #"\u3000"
                                                  #" "))) (nth seed-phrase-length (.indexOf entropy-sizes size))))
     (java.text.Normalizer/normalize seed-phrase java.text.Normalizer$Form/NFKD))))

(defn check-mnemonic
  "Check the validity of a mnemonic seed phrase.
  Return true if the provided mnemonic is valid."
  [mnemonic]
  (let [words (str/split mnemonic (if (.contains mnemonic "\u3000")
                                    #"\u3000"
                                    #" "))
        language (detect-language mnemonic)]
    (and (some #(= (count words) %)
               (map #(/ % 11)
                    (map + (range 128 (+ 1 256) 32)
                         (map #(/ % 32) (range 128 (+ 1 256) 32)))))
         (=
           (->> mnemonic
                (#(seed-phrase->binary-array % language))
                (take (* 11 (* 32 (/ (count words) 33))))
                (byte-array->digest)
                first
                Integer/toBinaryString
                Integer/parseInt
                (format "%08d")
                (take (* 11 (/ (count words) 33)))
                (apply str))
           (apply
             str
             (take-last
               (* 11 (/ (count words) 33))
               (seed-phrase->binary-array mnemonic language)))))))

(defn mnemonic->seed
  "Create a binary seed from the mnemonic"
  ([mnemonic]
   (mnemonic->seed mnemonic ""))
  ([mnemonic passphrase]
   (let [mnemonic (.toCharArray (Normalizer/normalize mnemonic
                                                      java.text.Normalizer$Form/NFKD))
         passphrase (Normalizer/normalize passphrase
                                          java.text.Normalizer$Form/NFKD)
         passphrase (str "mnemonic" passphrase)
         passphrase-bytes (StringUtils/getBytes passphrase StandardCharsets/UTF_8)

         skf (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA512")
         spec (PBEKeySpec. mnemonic passphrase-bytes 2048 512)
         key (.generateSecret skf spec)]
     (-> (.getEncoded key)
         (codecs/bytes->hex)))))
