module ESHelper
  def self.get_host_port
    if ENV["INTEGRATION"] == "true" || ENV["SECURE_INTEGRATION"] == "true"
      "elasticsearch:9200"
    else
      "localhost:9200" # for local running integration specs outside docker
    end
  end

  def self.get_client(options)
    require 'elasticsearch/transport/transport/http/faraday' # supports user/password options
    host, port = get_host_port.split(':')
    host_opts = { host: host, port: port, scheme: 'http' }
    ssl_opts = {}

    if options[:ca_file]
      ssl_opts = { ssl: true, ca_file: options[:ca_file], verify: false }
      host_opts[:scheme] = 'https'
    end

    if options[:user] && options[:password]
      host_opts[:user] = options[:user]
      host_opts[:password] = options[:password]
    end

    Elasticsearch::Client.new(hosts: [host_opts], ssl: ssl_opts,
                              transport_class: Elasticsearch::Transport::Transport::HTTP::Faraday)
  end

  def self.doc_type
    if ESHelper.es_version_satisfies?(">=8")
      nil
    elsif ESHelper.es_version_satisfies?(">=7")
      "_doc"
    else
      "doc"
    end
  end

  def self.index_doc(es, params)
    type = doc_type
    params[:type] = doc_type unless type.nil?
    es.index(params)
  end

  def self.es_version
    ENV['ES_VERSION'] || ENV['ELASTIC_STACK_VERSION']
  end

  def self.es_version_satisfies?(*requirement)
    es_version = RSpec.configuration.filter[:es_version] || ENV['ES_VERSION'] || ENV['ELASTIC_STACK_VERSION']
    if es_version.nil?
      puts "Info: ES_VERSION, ELASTIC_STACK_VERSION or 'es_version' tag wasn't set. Returning false to all `es_version_satisfies?` call."
      return false
    end
    es_release_version = Gem::Version.new(es_version).release
    Gem::Requirement.new(requirement).satisfied_by?(es_release_version)
  end
end