module ESHelper
  def self.get_host_port
    return "http://elasticsearch:9200" if ENV["INTEGRATION"] == "true"
    raise "This setting is only used for integration tests"
  end

  def self.get_client
    Elasticsearch::Client.new(:hosts => [get_host_port])
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