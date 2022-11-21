(ns parse-table
  (:require [clojure.string :as string]))

;; Reference: `https://github.com/yogthos/markdown-clj/blob/master/src/cljc/markdown/tables.cljc`
(defn parse-table-row [text]
  (->> text
       (#(if (= (first %) \|)
           (apply str (rest %))
           %))
       (string/trim)
       (#(string/split % #"\|"))
       (map string/trim)
       (map #(identity {:text %}))))

(defn format-row [row]
  {:coin_type (Integer/parseInt (:text (first row)))
   :symbol (:text (nth row 2))
   :coin (:text (nth row 3))})

(defn generate-edn [markdown-filename edn-filename]
  (-> (slurp markdown-filename)
      (string/split #"\n")
      (#(map (fn [x] (parse-table-row x)) %))
      (#(map (fn [x] (format-row x)) %))
      (#(spit edn-filename (prn-str %)))))

(comment
  (generate-edn "resources/coin_types.md" "resources/coin_types.edn"))
