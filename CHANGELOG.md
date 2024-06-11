## 4.20.3
  - [DOC] Update link to bypass redirect, resolving directly to correct content  [#206](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/206)

## 4.20.2
  - fix case when aggregation returns an error [#204](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/204)

## 4.20.1
  - Fix license header [#203](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/203)

## 4.20.0
  - Added `response_type` configuration option to allow processing result of aggregations [#202](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/202)

## 4.19.1
  - Plugin version bump to pick up docs fix in  [#199](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/199) required to clear build error in docgen. [#200](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/200)

## 4.19.0
  - Added `search_api` option to support `search_after` and `scroll` [#198](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/198)
    - The default value `auto` uses `search_after` for Elasticsearch >= 8, otherwise, fall back to `scroll` 

## 4.18.0
  - Added request header `Elastic-Api-Version` for serverless [#195](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/195)

## 4.17.2
  - Fixes a regression introduced in 4.17.0 which could prevent a connection from being established to Elasticsearch in some SSL configurations [#193](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/193)

## 4.17.1
  - Fix: scroll slice high memory consumption [#189](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/189)

## 4.17.0
  - Added SSL settings for: [#185](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/185)
    - `ssl_enabled`: Enable/disable the SSL settings. If not provided, the value is inferred from the hosts scheme
    - `ssl_certificate`: OpenSSL-style X.509 certificate file to authenticate the client
    - `ssl_key`: OpenSSL-style RSA private key that corresponds to the `ssl_certificate`
    - `ssl_truststore_path`: The JKS truststore to validate the server's certificate
    - `ssl_truststore_type`: The format of the truststore file
    - `ssl_truststore_password`: The truststore password
    - `ssl_keystore_path`: The keystore used to present a certificate to the server
    - `ssl_keystore_type`: The format of the keystore file
    - `ssl_keystore_password`: The keystore password
    - `ssl_cipher_suites`: The list of cipher suites to use
    - `ssl_supported_protocols`: Supported protocols with versions
  - Reviewed and deprecated SSL settings to comply with Logstash's naming convention
    - Deprecated `ssl` in favor of `ssl_enabled`
    - Deprecated `ca_file` in favor of `ssl_certificate_authorities`
    - Deprecated `ssl_certificate_verification` in favor of `ssl_verification_mode`

## 4.16.0
  - Added `ssl_certificate_verification` option to control SSL certificate verification [#180](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/180)

## 4.15.0
  - Feat: add `retries` option. allow retry for failing query [#179](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/179)

## 4.14.0
  - Refactor: switch to using scheduler mixin [#177](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/177)

## 4.13.0
  - Added support for `ca_trusted_fingerprint` when run on Logstash 8.3+ [#178](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/178)

## 4.12.3
  - Fix: update Elasticsearch Ruby client to correctly customize 'user-agent' header [#171](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/171)

## 4.12.2
  - Fix: hosts => "es_host:port" regression [#168](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/168)

## 4.12.1
  - Fixed too_long_frame_exception by passing scroll_id in the body [#159](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/159)

## 4.12.0
  - Feat: Update Elasticsearch client to 7.14.0 [#157](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/157)

## 4.11.0
  - Feat: add user-agent header passed to the Elasticsearch HTTP connection [#158](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/158)

## 4.10.0
  - Feat: added ecs_compatibility + event_factory support [#149](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/149)

## 4.9.3
  - Fixed SSL handshake hang indefinitely with proxy setup [#156](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/156)

## 4.9.2
  - Fix: a regression (in LS 7.14.0) where due the elasticsearch client update (from 5.0.5 to 7.5.0) the `Authorization`
    header isn't passed, this leads to the plugin not being able to leverage `user`/`password` credentials set by the user.
    [#153](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/153)

## 4.9.1
  - [DOC] Replaced hard-coded links with shared attributes [#143](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/143)
  - [DOC] Added missing quote to docinfo_fields example [#145](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/145)

## 4.9.0
  - Added `target` option, allowing the hit's source to target a specific field instead of being expanded at the root of the event. This allows the input to play nicer with the Elastic Common Schema when the input does not follow the schema. [#117](https://github.com/logstash-plugins/logstash-input-elasticsearch/issues/117)

## 4.8.3
  - [DOC] Fixed links to restructured Logstash-to-cloud docs [#139](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/139)

## 4.8.2
  - [DOC] Document the permissions required in secured clusters [#137](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/137)

## 4.8.1
  - Fixed connection error when using multiple `slices`. [#133](https://github.com/logstash-plugins/logstash-input-elasticsearch/issues/133)

## 4.8.0
  - Added the ability to configure connection-, request-, and socket-timeouts with `connect_timeout_seconds`, `request_timeout_seconds`, and `socket_timeout_seconds` [#121](https://github.com/logstash-plugins/logstash-input-elasticsearch/issues/121)

## 4.7.1
  - [DOC] Updated sliced scroll link to resolve to correct location after doc structure change [#135](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/135)
  - [DOC] Added usage example of docinfo metadata [#98](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/98)

## 4.7.0
  - Added api_key support [#131](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/131)

## 4.6.2
  - Added scroll clearing and better handling of scroll expiration [#128](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/128)

## 4.6.1
  - [DOC] Removed outdated compatibility notice [#124](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/124)

## 4.6.0
  - Feat: added option to specify proxy for ES [#114](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/114)

## 4.5.0
  - Feat: Added support for cloud_id / cloud_auth configuration [#112](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/112)

## 4.4.0
  - Changed Elasticsearch Client transport to use Manticore [#111](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/111)

## 4.3.3
  - Loosen restrictions on Elasticsearch gem [#110](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/110)

## 4.3.2
  - Fixed broken link to Elasticsearch Reference  [#106](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/106)

## 4.3.1
  - Fixed deeplink to Elasticsearch Reference  [#103](https://github.com/logstash-plugins/logstash-input-elasticsearch/pull/103)

## 4.3.0
  - Added managed slice scrolling with `slices` option

## 4.2.1
  - Docs: Set the default_codec doc attribute.

## 4.2.0
  - Docs: Deprecate `document_type`
  - Add support for scheduling periodic execution of the query #81

## 4.1.1
  - Update gemspec summary

## 4.1.0
 - Enable use of docinfo (@metadata) fields in `add_field` decorations

## 4.0.6
  - Docs: Fix link syntax

## 4.0.5
  - Fix some documentation issues

## 4.0.3
  - Docs: Add requirement to use version 4.0.2 or higher to support sending Content-Type headers
  - Fix scrolling to use json bodies in the requests (this makes scrolling not work in ES 1.x)

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
