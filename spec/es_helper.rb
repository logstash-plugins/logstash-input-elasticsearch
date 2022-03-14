module ESHelper
  def self.get_host_port
    if ENV["INTEGRATION"] == "true" || ENV["SECURE_INTEGRATION"] == "true"
      "elasticsearch:9200"
    else
      "localhost:9200" # for local running integration specs outside docker
    end
  end

  def self.curl_and_get_json_response(url, method: :get, args: nil); require 'open3'
    cmd = "curl -s -v --show-error #{args} -X #{method.to_s.upcase} -k #{url}"
    begin
      out, err, status = Open3.capture3(cmd)
    rescue Errno::ENOENT
      fail "curl not available, make sure curl binary is installed and available on $PATH"
    end

    if status.success?
      http_status = err.match(/< HTTP\/1.1 (.*?)/)[1] || '0' # < HTTP/1.1 200 OK\r\n
      if http_status.strip[0].to_i > 2
        warn out
        fail "#{cmd.inspect} unexpected response: #{http_status}\n\n#{err}"
      end

      LogStash::Json.load(out)
    else
      warn out
      fail "#{cmd.inspect} process failed: #{status}\n\n#{err}"
    end
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