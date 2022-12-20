;; Copyright © 2022 CicadaBank

;; Permission is hereby granted, free of charge, to any person obtaining a copy of
;; this software and associated documentation files (the "Software"), to deal in
;; the Software without restriction, including without limitation the rights to
;; use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
;; the Software, and to permit persons to whom the Software is furnished to do so,
;; subject to the following conditions:

;; The above copyright notice and this permission notice shall be included in all
;; copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
;; FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
;; COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
;; IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
