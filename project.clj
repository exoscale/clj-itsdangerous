(defproject exoscale/itsdangerous "0.1.3-SNAPSHOT"
  :description "Clojure incomplete port of https://palletsprojects.com/p/itsdangerous/"
  :url "https://github.com/exoscale/clj-itsdangerous"
  :license {:name "MIT/ISC"
            :url  "https://github.com/exoscale/clj-kubernetes-api/blob/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [exoscale/ex        "0.3.9"]
                 [spootnik/constance "0.5.4"]]
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :pedantic? :abort
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]
                   :plugins      [[lein-cljfmt "0.6.7"]]
                   :pedantic?    :warn
                   :global-vars  {*warn-on-reflection* true}}})
