(ns build
  (:require
    [clojure.pprint :as pp]
    [clojure.tools.build.api :as tools]
    [deps-deploy.deps-deploy :as deploy]))

(def lib 'org.clojars.cicadabank/proposals)
(def version "0.1")
(def class-dir "classes")
(def basis (tools/create-basis {:project "deps.edn"}))
(def jar-file (format "%s-%s.jar" (name lib) version))
(def target-dir "target/")

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
  (tools/jar {:class-dir class-dir
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

;; Improve it to accept gpg keys
;; see https://github.com/Flexiana/framework/blob/main/.github/clojars_deploy.clj
(defn deploy
  "Deploy the JAR artifact to Clojars repository."
  [_]
  (deploy/deploy {:installer :remote
                  :artifact (str target-dir jar-file)
                  :pom-file (tools/pom-path {:lib lib
                                             :class-dir (str target-dir class-dir)})}))
