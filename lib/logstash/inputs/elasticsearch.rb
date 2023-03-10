# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/json"
require "logstash/util/safe_uri"
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'
require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/ecs_compatibility_support/target_check'
require 'logstash/plugin_mixins/ca_trusted_fingerprint_support'
require "logstash/plugin_mixins/scheduler"
require "logstash/plugin_mixins/normalize_config_support"
require "base64"
require 'logstash/helpers/loggable_try'

require "elasticsearch"
require "elasticsearch/transport/transport/http/manticore"
require_relative "elasticsearch/patches/_elasticsearch_transport_http_manticore"
require_relative "elasticsearch/patches/_elasticsearch_transport_connections_selector"

# .Compatibility Note
# [NOTE]
# ================================================================================
# Starting with Elasticsearch 5.3, there's an {ref}modules-http.html[HTTP setting]
# called `http.content_type.required`. If this option is set to `true`, and you
# are using Logstash 2.4 through 5.2, you need to update the Elasticsearch input
# plugin to version 4.0.2 or higher.
# 
# ================================================================================
# 
# Read from an Elasticsearch cluster, based on search query results.
# This is useful for replaying test logs, reindexing, etc.
# It also supports periodically scheduling lookup enrichments
# using a cron syntax (see `schedule` setting).
#
# Example:
# [source,ruby]
#     input {
#       # Read all documents from Elasticsearch matching the given query
#       elasticsearch {
#         hosts => "localhost"
#         query => '{ "query": { "match": { "statuscode": 200 } }, "sort": [ "_doc" ] }'
#       }
#     }
#
# This would create an Elasticsearch query with the following format:
# [source,json]
#     curl 'http://localhost:9200/logstash-*/_search?&scroll=1m&size=1000' -d '{
#       "query": {
#         "match": {
#           "statuscode": 200
#         }
#       },
#       "sort": [ "_doc" ]
#     }'
#
# ==== Scheduling
#
# Input from this plugin can be scheduled to run periodically according to a specific
# schedule. This scheduling syntax is powered by https://github.com/jmettraux/rufus-scheduler[rufus-scheduler].
# The syntax is cron-like with some extensions specific to Rufus (e.g. timezone support ).
#
# Examples:
#
# |==========================================================
# | `* 5 * 1-3 *`               | will execute every minute of 5am every day of January through March.
# | `0 * * * *`                 | will execute on the 0th minute of every hour every day.
# | `0 6 * * * America/Chicago` | will execute at 6:00am (UTC/GMT -5) every day.
# |==========================================================
#
#
# Further documentation describing this syntax can be found https://github.com/jmettraux/rufus-scheduler#parsing-cronlines-and-time-strings[here].
#
#
class LogStash::Inputs::Elasticsearch < LogStash::Inputs::Base

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  include LogStash::PluginMixins::ECSCompatibilitySupport::TargetCheck

  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter

  extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

  include LogStash::PluginMixins::Scheduler

  include LogStash::PluginMixins::NormalizeConfigSupport

  config_name "elasticsearch"

  # List of elasticsearch hosts to use for querying.
  # Each host can be either IP, HOST, IP:port or HOST:port.
  # Port defaults to 9200
  config :hosts, :validate => :array

  # The index or alias to search.
  config :index, :validate => :string, :default => "logstash-*"

  # The query to be executed. Read the Elasticsearch query DSL documentation
  # for more info
  # https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
  config :query, :validate => :string, :default => '{ "sort": [ "_doc" ] }'

  # This allows you to set the maximum number of hits returned per scroll.
  config :size, :validate => :number, :default => 1000

  # The number of retries to run the query. If the query fails after all retries, it logs an error message.
  config :retries, :validate => :number, :default => 0

  # This parameter controls the keepalive time in seconds of the scrolling
  # request and initiates the scrolling process. The timeout applies per
  # round trip (i.e. between the previous scroll request, to the next).
  config :scroll, :validate => :string, :default => "1m"

  # This parameter controls the number of parallel slices to be consumed simultaneously
  # by this pipeline input.
  config :slices, :validate => :number

  # If set, include Elasticsearch document information such as index, type, and
  # the id in the event.
  #
  # It might be important to note, with regards to metadata, that if you're
  # ingesting documents with the intent to re-index them (or just update them)
  # that the `action` option in the elasticsearch output wants to know how to
  # handle those things. It can be dynamically assigned with a field
  # added to the metadata.
  #
  # Example
  # [source, ruby]
  #     input {
  #       elasticsearch {
  #         hosts => "es.production.mysite.org"
  #         index => "mydata-2018.09.*"
  #         query => "*"
  #         size => 500
  #         scroll => "5m"
  #         docinfo => true
  #       }
  #     }
  #     output {
  #       elasticsearch {
  #         index => "copy-of-production.%{[@metadata][_index]}"
  #         document_type => "%{[@metadata][_type]}"
  #         document_id => "%{[@metadata][_id]}"
  #       }
  #     }
  #
  config :docinfo, :validate => :boolean, :default => false

  # Where to move the Elasticsearch document information.
  # default: [@metadata][input][elasticsearch] in ECS mode, @metadata field otherwise
  config :docinfo_target, :validate=> :field_reference

  # List of document metadata to move to the `docinfo_target` field.
  # To learn more about Elasticsearch metadata fields read
  # http://www.elasticsearch.org/guide/en/elasticsearch/guide/current/_document_metadata.html
  config :docinfo_fields, :validate => :array, :default => ['_index', '_type', '_id']

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # Connection Timeout, in Seconds
  config :connect_timeout_seconds, :validate => :positive_whole_number, :default => 10

  # Request Timeout, in Seconds
  config :request_timeout_seconds, :validate => :positive_whole_number, :default => 60

  # Socket Timeout, in Seconds
  config :socket_timeout_seconds, :validate => :positive_whole_number, :default => 60

  # Cloud ID, from the Elastic Cloud web console. If set `hosts` should not be used.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_id[Logstash-to-Cloud documentation]
  config :cloud_id, :validate => :string

  # Cloud authentication string ("<username>:<password>" format) is an alternative for the `user`/`password` configuration.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_auth[Logstash-to-Cloud documentation]
  config :cloud_auth, :validate => :password

  # Authenticate using Elasticsearch API key.
  # format is id:api_key (as returned by https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html[Create API key])
  config :api_key, :validate => :password

  # Set the address of a forward HTTP proxy.
  config :proxy, :validate => :uri_or_empty

  # SSL
  config :ssl, :validate => :boolean, :default => false, :deprecated => "Set 'ssl_enabled' instead."

  # SSL Certificate Authority file in PEM encoded format, must also include any chain certificates as necessary
  config :ca_file, :validate => :path, :deprecated => "Set 'ssl_certificate_authorities' instead."

  # OpenSSL-style X.509 certificate certificate to authenticate the client
  config :ssl_certificate, :validate => :path

  # SSL Certificate Authority files in PEM encoded format, must also include any chain certificates as necessary
  config :ssl_certificate_authorities, :validate => :path, :list => true

  # Option to validate the server's certificate. Disabling this severely compromises security.
  # For more information on the importance of certificate verification please read
  # https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf
  config :ssl_certificate_verification, :validate => :boolean, :default => true, :deprecated => "Set 'ssl_verification_mode' instead."

  # The list of cipher suites to use, listed by priorities.
  # Supported cipher suites vary depending on which version of Java is used.
  config :ssl_cipher_suites, :validate => :string, :list => true

  # SSL
  config :ssl_enabled, :validate => :boolean

  # OpenSSL-style RSA private key to authenticate the client
  config :ssl_key, :validate => :path

  # Set the keystore password
  config :ssl_keystore_password, :validate => :password

  # The keystore used to present a certificate to the server.
  # It can be either .jks or .p12
  config :ssl_keystore_path, :validate => :path

  # The format of the keystore file. It must be either jks or pkcs12
  config :ssl_keystore_type, :validate => %w[pkcs12 jks]

  # Supported protocols with versions.
  config :ssl_supported_protocols, :validate => %w[TLSv1.1 TLSv1.2 TLSv1.3], :default => [], :list => true

  # Set the truststore password
  config :ssl_truststore_password, :validate => :password

  # The JKS truststore to validate the server's certificate.
  # Use either `:ssl_truststore_path` or `:ssl_certificate_authorities`
  config :ssl_truststore_path, :validate => :path

  # The format of the truststore file. It must be either jks or pkcs12
  config :ssl_truststore_type, :validate => %w[pkcs12 jks]

  # Options to verify the server's certificate.
  # "full": validates that the provided certificate has an issue date that’s within the not_before and not_after dates;
  # chains to a trusted Certificate Authority (CA); has a hostname or IP address that matches the names within the certificate.
  # "none": performs no certificate validation. Disabling this severely compromises security (https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)
  config :ssl_verification_mode, :validate => %w[full none], :default => 'full'

  # Schedule of when to periodically run statement, in Cron format
  # for example: "* * * * *" (execute query every minute, on the minute)
  #
  # There is no schedule by default. If no schedule is given, then the statement is run
  # exactly once.
  config :schedule, :validate => :string

  # If set, the _source of each hit will be added nested under the target instead of at the top-level
  config :target, :validate => :field_reference

  # config :ca_trusted_fingerprint, :validate => :sha_256_hex
  include LogStash::PluginMixins::CATrustedFingerprintSupport

  def initialize(params={})
    super(params)

    if docinfo_target.nil?
      @docinfo_target = ecs_select[disabled: '@metadata', v1: '[@metadata][input][elasticsearch]']
    end
  end

  def register
    require "rufus/scheduler"

    fill_hosts_from_cloud_id
    setup_ssl_params!

    @options = {
      :index => @index,
      :scroll => @scroll,
      :size => @size
    }
    @base_query = LogStash::Json.load(@query)
    if @slices
      @base_query.include?('slice') && fail(LogStash::ConfigurationError, "Elasticsearch Input Plugin's `query` option cannot specify specific `slice` when configured to manage parallel slices with `slices` option")
      @slices < 1 && fail(LogStash::ConfigurationError, "Elasticsearch Input Plugin's `slices` option must be greater than zero, got `#{@slices}`")
    end

    @retries < 0 && fail(LogStash::ConfigurationError, "Elasticsearch Input Plugin's `retries` option must be equal or greater than zero, got `#{@retries}`")

    validate_authentication
    fill_user_password_from_cloud_auth

    transport_options = {:headers => {}}
    transport_options[:headers].merge!(setup_basic_auth(user, password))
    transport_options[:headers].merge!(setup_api_key(api_key))
    transport_options[:headers].merge!({'user-agent' => prepare_user_agent()})
    transport_options[:request_timeout] = @request_timeout_seconds unless @request_timeout_seconds.nil?
    transport_options[:connect_timeout] = @connect_timeout_seconds unless @connect_timeout_seconds.nil?
    transport_options[:socket_timeout]  = @socket_timeout_seconds  unless @socket_timeout_seconds.nil?

    hosts = setup_hosts
    ssl_options = setup_client_ssl

    @logger.warn "Supplied proxy setting (proxy => '') has no effect" if @proxy.eql?('')

    transport_options[:proxy] = @proxy.to_s if @proxy && !@proxy.eql?('')

    @client = Elasticsearch::Client.new(
      :hosts => hosts,
      :transport_options => transport_options,
      :transport_class => ::Elasticsearch::Transport::Transport::HTTP::Manticore,
      :ssl => ssl_options
    )
    test_connection!
    @client
  end


  def run(output_queue)
    if @schedule
      scheduler.cron(@schedule) { do_run(output_queue) }
      scheduler.join
    else
      do_run(output_queue)
    end
  end

  private
  JOB_NAME = "run query"
  def do_run(output_queue)
    # if configured to run a single slice, don't bother spinning up threads
    if @slices.nil? || @slices <= 1
      success, events = retryable_slice
      success && events.each { |event| output_queue << event }
      return
    end

    logger.warn("managed slices for query is very large (#{@slices}); consider reducing") if @slices > 8

    slice_results = parallel_slice # array of tuple(ok, events)

    # insert events to queue if all slices success
    if slice_results.all?(&:first)
      slice_results.flat_map { |success, events| events }
                  .each { |event| output_queue << event }
    end

    logger.trace("#{@slices} slices completed")
  end

  def retryable(job_name, &block)
    begin
      stud_try = ::LogStash::Helpers::LoggableTry.new(logger, job_name)
      output = stud_try.try((@retries + 1).times) { yield }
      [true, output]
    rescue => e
      error_details = {:message => e.message, :cause => e.cause}
      error_details[:backtrace] = e.backtrace if logger.debug?
      logger.error("Tried #{job_name} unsuccessfully", error_details)
      [false, nil]
    end
  end


  # @return [(ok, events)] : Array of tuple(Boolean, [Logstash::Event])
  def parallel_slice
    pipeline_id = execution_context&.pipeline_id || 'main'
    @slices.times.map do |slice_id|
      Thread.new do
        LogStash::Util::set_thread_name("[#{pipeline_id}]|input|elasticsearch|slice_#{slice_id}")
        retryable_slice(slice_id)
      end
    end.map do |t|
      t.join
      t.value
    end
  end

  # @param scroll_id [Integer]
  # @return (ok, events) [Boolean, Array(Logstash::Event)]
  def retryable_slice(slice_id=nil)
    retryable(JOB_NAME) do
      output = []
      do_run_slice(output, slice_id)
      output
    end
  end


  def do_run_slice(output_queue, slice_id=nil)
    slice_query = @base_query
    slice_query = slice_query.merge('slice' => { 'id' => slice_id, 'max' => @slices}) unless slice_id.nil?

    slice_options = @options.merge(:body => LogStash::Json.dump(slice_query) )

    logger.info("Slice starting", slice_id: slice_id, slices: @slices) unless slice_id.nil?

    begin
      r = search_request(slice_options)

      r['hits']['hits'].each { |hit| push_hit(hit, output_queue) }
      logger.debug("Slice progress", slice_id: slice_id, slices: @slices) unless slice_id.nil?

      has_hits = r['hits']['hits'].any?
      scroll_id = r['_scroll_id']

      while has_hits && scroll_id && !stop?
        has_hits, scroll_id = process_next_scroll(output_queue, scroll_id)
        logger.debug("Slice progress", slice_id: slice_id, slices: @slices) if logger.debug? && slice_id
      end
      logger.info("Slice complete", slice_id: slice_id, slices: @slices) unless slice_id.nil?
    ensure
      clear_scroll(scroll_id)
    end
  end

  ##
  # @param output_queue [#<<]
  # @param scroll_id [String]: a scroll id to resume
  # @return [Array(Boolean,String)]: a tuple representing whether the response
  #
  def process_next_scroll(output_queue, scroll_id)
    r = scroll_request(scroll_id)
    r['hits']['hits'].each { |hit| push_hit(hit, output_queue) }
    [r['hits']['hits'].any?, r['_scroll_id']]
  end

  def push_hit(hit, output_queue)
    event = targeted_event_factory.new_event hit['_source']
    set_docinfo_fields(hit, event) if @docinfo
    decorate(event)
    output_queue << event
  end

  def set_docinfo_fields(hit, event)
    # do not assume event[@docinfo_target] to be in-place updatable. first get it, update it, then at the end set it in the event.
    docinfo_target = event.get(@docinfo_target) || {}

    unless docinfo_target.is_a?(Hash)
      @logger.error("Incompatible Event, incompatible type for the docinfo_target=#{@docinfo_target} field in the `_source` document, expected a hash got:", :docinfo_target_type => docinfo_target.class, :event => event.to_hash_with_metadata)

      # TODO: (colin) I am not sure raising is a good strategy here?
      raise Exception.new("Elasticsearch input: incompatible event")
    end

    @docinfo_fields.each do |field|
      docinfo_target[field] = hit[field]
    end

    event.set(@docinfo_target, docinfo_target)
  end

  def clear_scroll(scroll_id)
    @client.clear_scroll(:body => { :scroll_id => scroll_id }) if scroll_id
  rescue => e
    # ignore & log any clear_scroll errors
    logger.warn("Ignoring clear_scroll exception", message: e.message, exception: e.class)
  end

  def scroll_request(scroll_id)
    @client.scroll(:body => { :scroll_id => scroll_id }, :scroll => @scroll)
  end

  def search_request(options)
    @client.search(options)
  end

  def hosts_default?(hosts)
    hosts.nil? || ( hosts.is_a?(Array) && hosts.empty? )
  end

  def effectively_ssl?
    return true if @ssl_enabled

    hosts = Array(@hosts)
    return false if hosts.nil? || hosts.empty?

    hosts.all? { |host| host && host.to_s.start_with?("https") }
  end

  def validate_authentication
    authn_options = 0
    authn_options += 1 if @cloud_auth
    authn_options += 1 if (@api_key && @api_key.value)
    authn_options += 1 if (@user || (@password && @password.value))

    if authn_options > 1
      raise LogStash::ConfigurationError, 'Multiple authentication options are specified, please only use one of user/password, cloud_auth or api_key'
    end

    if @api_key && @api_key.value && @ssl_enabled != true
      raise(LogStash::ConfigurationError, "Using api_key authentication requires SSL/TLS secured communication using the `ssl_enabled => true` option")
    end
  end

  def setup_client_ssl
    ssl_options = {}
    ssl_options[:ssl] = true if @ssl_enabled

    unless @ssl_enabled
      # Keep it backward compatible with the deprecated `ssl` option
      ssl_options[:trust_strategy] = trust_strategy_for_ca_trusted_fingerprint if original_params.include?('ssl')
      return ssl_options
    end

    ssl_certificate_authorities, ssl_truststore_path, ssl_certificate, ssl_keystore_path = params.values_at('ssl_certificate_authorities', 'ssl_truststore_path', 'ssl_certificate', 'ssl_keystore_path')

    if ssl_certificate_authorities && ssl_truststore_path
      raise LogStash::ConfigurationError, 'Use either "ssl_certificate_authorities/ca_file" or "ssl_truststore_path" when configuring the CA certificate'
    end

    if ssl_certificate && ssl_keystore_path
      raise LogStash::ConfigurationError, 'Use either "ssl_certificate" or "ssl_keystore_path/keystore" when configuring client certificates'
    end

    if ssl_certificate_authorities&.any?
      raise LogStash::ConfigurationError, 'Multiple values on "ssl_certificate_authorities" are not supported by this plugin' if ssl_certificate_authorities.size > 1
      ssl_options[:ca_file] = ssl_certificate_authorities.first
    end

    if ssl_truststore_path
      ssl_options[:truststore] = ssl_truststore_path
      ssl_options[:truststore_type] = params["ssl_truststore_type"] if params.include?("ssl_truststore_type")
      ssl_options[:truststore_password] = params["ssl_truststore_password"].value if params.include?("ssl_truststore_password")
    end

    if ssl_keystore_path
      ssl_options[:keystore] = ssl_keystore_path
      ssl_options[:keystore_type] = params["ssl_keystore_type"] if params.include?("ssl_keystore_type")
      ssl_options[:keystore_password] = params["ssl_keystore_password"].value if params.include?("ssl_keystore_password")
    end

    ssl_key = params["ssl_key"]
    if ssl_certificate
      raise LogStash::ConfigurationError, 'Using an "ssl_certificate" requires an "ssl_key"' unless ssl_key
      ssl_options[:client_cert] = ssl_certificate
      ssl_options[:client_key] = ssl_key
    elsif !ssl_key.nil?
      raise LogStash::ConfigurationError, 'An "ssl_certificate" is required when using an "ssl_key"'
    end

    ssl_verification_mode = params["ssl_verification_mode"]
    unless ssl_verification_mode.nil?
      case ssl_verification_mode
        when 'none'
          logger.warn "You have enabled encryption but DISABLED certificate verification, " +
                        "to make sure your data is secure set `ssl_verification_mode => full`"
          ssl_options[:verify] = :disable
        else
          ssl_options[:verify] = :strict
      end
    end

    ssl_options[:cipher_suites] = params["ssl_cipher_suites"] if params.include?("ssl_cipher_suites")

    protocols = params['ssl_supported_protocols']
    ssl_options[:protocols] = protocols if protocols&.any?
    ssl_options[:trust_strategy] = trust_strategy_for_ca_trusted_fingerprint

    ssl_options
  end

  def setup_ssl_params!
    @ssl_enabled = normalize_config(:ssl_enabled) do |normalize|
      normalize.with_deprecated_alias(:ssl)
    end

    # Infer the value if neither the deprecate `ssl` and `ssl_enabled` were set
    infer_ssl_enabled_from_hosts

    @ssl_certificate_authorities = normalize_config(:ssl_certificate_authorities) do |normalize|
      normalize.with_deprecated_mapping(:ca_file) do |ca_file|
        [ca_file]
      end
    end

    @ssl_verification_mode = normalize_config(:ssl_verification_mode) do |normalize|
      normalize.with_deprecated_mapping(:ssl_certificate_verification) do |ssl_certificate_verification|
        if ssl_certificate_verification == true
          "full"
        else
          "none"
        end
      end
    end

    params['ssl_enabled'] = @ssl_enabled
    params['ssl_certificate_authorities'] = @ssl_certificate_authorities unless @ssl_certificate_authorities.nil?
    params['ssl_verification_mode'] = @ssl_verification_mode unless @ssl_verification_mode.nil?
  end

  def infer_ssl_enabled_from_hosts
    return if original_params.include?('ssl') || original_params.include?('ssl_enabled')

    @ssl_enabled = params['ssl_enabled'] = effectively_ssl?
  end

  def setup_hosts
    @hosts = Array(@hosts).map { |host| host.to_s } # potential SafeURI#to_s
    @hosts.map do |h|
      if h.start_with?('http:', 'https:')
        h
      else
        host, port = h.split(':')
        { host: host, port: port, scheme: (@ssl_enabled ? 'https' : 'http') }
      end
    end
  end

  def setup_basic_auth(user, password)
    return {} unless user && password && password.value

    token = ::Base64.strict_encode64("#{user}:#{password.value}")
    { 'Authorization' => "Basic #{token}" }
  end

  def setup_api_key(api_key)
    return {} unless (api_key && api_key.value)

    token = ::Base64.strict_encode64(api_key.value)
    { 'Authorization' => "ApiKey #{token}" }
  end

  def prepare_user_agent
      os_name = java.lang.System.getProperty('os.name')
      os_version = java.lang.System.getProperty('os.version')
      os_arch = java.lang.System.getProperty('os.arch')
      jvm_vendor = java.lang.System.getProperty('java.vendor')
      jvm_version = java.lang.System.getProperty('java.version')

      plugin_version = Gem.loaded_specs["logstash-input-elasticsearch"].version
      # example: logstash/7.14.1 (OS=Linux-5.4.0-84-generic-amd64; JVM=AdoptOpenJDK-11.0.11) logstash-input-elasticsearch/4.10.0
      "logstash/#{LOGSTASH_VERSION} (OS=#{os_name}-#{os_version}-#{os_arch}; JVM=#{jvm_vendor}-#{jvm_version}) logstash-#{@plugin_type}-#{config_name}/#{plugin_version}"
  end

  def fill_user_password_from_cloud_auth
    return unless @cloud_auth

    @user, @password = parse_user_password_from_cloud_auth(@cloud_auth)
    params['user'], params['password'] = @user, @password
  end

  def fill_hosts_from_cloud_id
    return unless @cloud_id

    if @hosts && !hosts_default?(@hosts)
      raise LogStash::ConfigurationError, 'Both cloud_id and hosts specified, please only use one of those.'
    end
    @hosts = parse_host_uri_from_cloud_id(@cloud_id)
  end

  def parse_host_uri_from_cloud_id(cloud_id)
    begin # might not be available on older LS
      require 'logstash/util/cloud_setting_id'
    rescue LoadError
      raise LogStash::ConfigurationError, 'The cloud_id setting is not supported by your version of Logstash, ' +
          'please upgrade your installation (or set hosts instead).'
    end

    begin
      cloud_id = LogStash::Util::CloudSettingId.new(cloud_id) # already does append ':{port}' to host
    rescue ArgumentError => e
      raise LogStash::ConfigurationError, e.message.to_s.sub(/Cloud Id/i, 'cloud_id')
    end
    cloud_uri = "#{cloud_id.elasticsearch_scheme}://#{cloud_id.elasticsearch_host}"
    LogStash::Util::SafeURI.new(cloud_uri)
  end

  def parse_user_password_from_cloud_auth(cloud_auth)
    begin # might not be available on older LS
      require 'logstash/util/cloud_setting_auth'
    rescue LoadError
      raise LogStash::ConfigurationError, 'The cloud_auth setting is not supported by your version of Logstash, ' +
          'please upgrade your installation (or set user/password instead).'
    end

    cloud_auth = cloud_auth.value if cloud_auth.is_a?(LogStash::Util::Password)
    begin
      cloud_auth = LogStash::Util::CloudSettingAuth.new(cloud_auth)
    rescue ArgumentError => e
      raise LogStash::ConfigurationError, e.message.to_s.sub(/Cloud Auth/i, 'cloud_auth')
    end
    [ cloud_auth.username, cloud_auth.password ]
  end

  # @private used by unit specs
  attr_reader :client

  def test_connection!
    @client.ping
  rescue Elasticsearch::UnsupportedProductError
    raise LogStash::ConfigurationError, "Could not connect to a compatible version of Elasticsearch"
  end

  module URIOrEmptyValidator
    ##
    # @override to provide :uri_or_empty validator
    # @param value [Array<Object>]
    # @param validator [nil,Array,Symbol]
    # @return [Array(true,Object)]: if validation is a success, a tuple containing `true` and the coerced value
    # @return [Array(false,String)]: if validation is a failure, a tuple containing `false` and the failure reason.
    def validate_value(value, validator)
      return super unless validator == :uri_or_empty

      value = deep_replace(value)
      value = hash_or_array(value)

      return true, value.first if value.size == 1 && value.first.empty?

      return super(value, :uri)
    end
  end
  extend(URIOrEmptyValidator)

  module PositiveWholeNumberValidator
    ##
    # @override to provide :positive_whole_number validator
    # @param value [Array<Object>]
    # @param validator [nil,Array,Symbol]
    # @return [Array(true,Object)]: if validation is a success, a tuple containing `true` and the coerced value
    # @return [Array(false,String)]: if validation is a failure, a tuple containing `false` and the failure reason.
    def validate_value(value, validator)
      return super unless validator == :positive_whole_number

      is_number, coerced_number = super(value, :number)

      return [true, coerced_number.to_i] if is_number && coerced_number.denominator == 1 && coerced_number > 0

      return [false, "Expected positive whole number, got `#{value.inspect}`"]
    end
  end
  extend(PositiveWholeNumberValidator)
end
