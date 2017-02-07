## 4.0.2
  - Bump ES client to 5.0.2 to get content-type: json behavior
  - Revert unneeded manticore change 

## 4.0.1
  - Switch internal HTTP client to support TLSv1.2
  - Upgrade ES client internally to better support ES 5.x

## 4.0.0
  - Remove `scan` from list of options as this is no longer allowed in
    Elasticsearch 5.0.
  - Change default query to sort by \_doc, as this replicates the `scan`
    behavior
  - Improve documentation to show sort by \_doc, and how to add it to custom
    queries.
    
## 3.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.1
  - Republish all the gems under jruby.
## 3.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
# 2.0.5
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.4
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.3
 - Refactored field references and cleanups

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

## 1.0.2 (September 3 - 2015)
 - fix scan/scroll response handling

## 1.0.1
 - refactor request logic into own method (better memory gc perf)
