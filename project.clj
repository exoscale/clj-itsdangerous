(defproject exoscale/itsdangerous "0.1.0"
  :description "Clojure incomplete port of https://palletsprojects.com/p/itsdangerous/"
  :url "https://github.com/exoscale/clj-itsdangerous"
  :license {:name "MIT"
            :url "https://github.com/exoscale/clj-kubernetes-api/blob/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.10.0" :scope "provided"]
                 [org.clojure/test.check "0.9.0" :scope "test"]
                 [buddy/buddy-core "1.5.0"]
                 [buddy/buddy-sign "3.0.0"]]
  :plugins [[exoscale/sos-wagon-private "1.3.2-exoscale8"]]
  :codox {:namespaces [#"itsdangerous"]}
  :repositories [["private" {:url "s3p://exo-artifacts/releases" :no-auth true :sign-releases false}]]
  :profiles {:dev {:plugins [[lein-codox "0.10.5"]]
             :global-vars {*warn-on-reflection* true}}})
