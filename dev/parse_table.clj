(ns parse-table
  (:require
    [clojure.string :as string]))

(defn parse-table-row
  "Parse text that represents a row of a table into a sequence of values
  that can be processed later.  For example, if the text argument is
  | foo | bar | baz | , the function will return the following sequence:
  [{:text \"foo\"}, {:text \"bar\"}, {:text \"baz\"}]
  Reference: `https://github.com/yogthos/markdown-clj/blob/master/src/cljc/markdown/tables.cljc`"
  [text]
  (->> text
       (#(if (= (first %) \|)
           (apply str (rest %))
           %))
       (string/trim)
       (#(string/split % #"\|"))
       (map string/trim)
       (map #(identity {:text %}))))

(defn format-row
  "Convert a sequence of values parsed from a table row into a more
  convenient format for further processing."
  [row]
  {:coin-type (Integer/parseInt (:text (first row)))
   :symbol (:text (nth row 2))
   :coin (:text (nth row 3))})

(defn generate-edn
  "`generate-edn` function is used to convert data from a Markdown file
  into EDN format. This data may be in the form of a table, with each
  line of the Markdown file representing a row in the table. The
  `generate-edn` function uses the `parse-table-row` and `format-row`
  functions to parse and format this data, respectively, and then
  writes the resulting sequence of maps to an EDN file."
  [markdown-filename edn-filename]
  (-> (slurp markdown-filename)
      (string/split #"\n")
      (#(map (fn [x] (parse-table-row x)) %))
      (#(map (fn [x] (format-row x)) %))
      (#(spit edn-filename (prn-str %)))))

(comment
  (generate-edn "resources/coin_types.md" "resources/coin_types.edn"))
