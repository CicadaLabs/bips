(ns build
  (:require
    [clojure.edn :as edn]
    [clojure.pprint :as pp]
    [clojure.tools.build.api :as tools]))

(def release-edn
  (edn/read-string (slurp "release.edn")))

;; TODO: how to define that using release-edn?
(def lib 'com.cicadabank/bips)

(def version (:version release-edn))

(def class-dir "classes")
(def basis (tools/create-basis {:project "deps.edn"}))
(def jar-file (format "%s-%s.jar" (name lib) version))
(def target-dir "target/")

(def clojars-deploy-user (System/getenv "CLOJARS_USERNAME"))
(def clojars-deploy-token (System/getenv "CLOJARS_PASSWORD"))
(def gpg-keys (System/getenv "GPG_SECRET_KEYS"))
(def gpg-ownertrust (System/getenv "GPG_OWNERTRUST"))

(defn clean
  "Clears the target directory, removing all files."
  [_]
  (tools/delete {:path target-dir}))

(defn jar
  "Package the library by creating a JAR file into \"target/\" dir."
  [{:keys [target] :or {target target-dir} :as params}]
  (pp/pprint (str "Target file: " target jar-file))
  (tools/write-pom {:class-dir (str target class-dir)
                    :lib lib
                    :version version
                    :basis basis
                    :src-dirs ["src"]})
  (tools/copy-dir {:src-dirs ["src" "resources"]
                   :target-dir (str target class-dir)})
  (tools/jar {:class-dir (str target class-dir)
              :jar-file (str target jar-file)}))

(defn install
  "Install JAR file into Maven local repository."
  [_]
  (pp/pprint "Installing JAR file to Maven's local repository")
  (tools/install {:basis      basis
                  :lib        lib
                  :version    version
                  :jar-file   (str target-dir jar-file)
                  :class-dir  class-dir}))

(def jar-n-install (comp install jar))
