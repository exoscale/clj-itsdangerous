(defproject exoscale/itsdangerous "0.0.0"                   ;; VERSION IS NOT USED ... see build.clj
  :description "Clojure incomplete port of https://palletsprojects.com/p/itsdangerous/"
  :url "https://github.com/exoscale/clj-itsdangerous"
  :license {:name "MIT/ISC"
            :url  "https://github.com/exoscale/clj-kubernetes-api/blob/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.12.4"]
                 [org.clojure/data.json "2.5.2"]
                 [exoscale/ex        "0.4.2"]
                 [exoscale/cloak     "1.0.42"]
                 [spootnik/constance "0.5.4"]]
  :pedantic? :abort
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]
                   :plugins      [[lein-cljfmt "0.6.7"]]
                   :pedantic?    :warn
                   :global-vars  {*warn-on-reflection* true}}})
