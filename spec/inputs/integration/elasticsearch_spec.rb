# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/inputs/elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Inputs::Elasticsearch do

  SECURE_INTEGRATION = ENV['SECURE_INTEGRATION'].eql? 'true'

  let(:config)   { { 'hosts' => ["http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}"],
                     'index' => 'logs',
                     'query' => '{ "query": { "match": { "message": "Not found"} }}' } }

  let(:plugin) { described_class.new(config) }
  let(:event)  { LogStash::Event.new({}) }
  let(:client_options) { Hash.new }

  let(:user) { ENV['ELASTIC_USER'] || 'simpleuser' }
  let(:password) { ENV['ELASTIC_PASSWORD'] || 'abc123' }
  let(:ca_file) { "spec/fixtures/test_certs/ca.crt" }

  let(:es_url) { "http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}" }

  let(:curl_args) do
    config['user'] ? "-u #{config['user']}:#{config['password']}" : ''
  end

  before(:each) do
    # Delete all templates first.
    # Clean ES of data before we start.
    ESHelper.curl_and_get_json_response "#{es_url}/_index_template/*", method: 'DELETE', args: curl_args
    # This can fail if there are no indexes, ignore failure.
    ESHelper.curl_and_get_json_response( "#{es_url}/_index/*", method: 'DELETE', args: curl_args) rescue nil
    doc_args = "#{curl_args} -H 'Content-Type: application/json' -d '{\"response\": 404, \"message\":\"Not Found\"}'"
    10.times do
      ESHelper.curl_and_get_json_response "#{es_url}/logs/_doc", method: 'POST', args: doc_args
    end
    ESHelper.curl_and_get_json_response "#{es_url}/_refresh", method: 'POST', args: curl_args
  end

  after(:each) do
    ESHelper.curl_and_get_json_response "#{es_url}/_index_template/*", method: 'DELETE', args: curl_args
    # This can fail if there are no indexes, ignore failure.
    ESHelper.curl_and_get_json_response( "#{es_url}/_index/*", method: 'DELETE', args: curl_args) rescue nil
    ESHelper.curl_and_get_json_response( "#{es_url}/logs", method: 'DELETE', args: curl_args) rescue nil
    ESHelper.curl_and_get_json_response "#{es_url}/_refresh", method: 'POST', args: curl_args
  end

  shared_examples 'an elasticsearch index plugin' do
    before(:each) do
      plugin.register
    end

    it 'should retrieve json event from elasticsearch' do
      queue = []
      plugin.run(queue)
      expect(queue.size).to eq(10)
      event = queue.pop
      expect(event).to be_a(LogStash::Event)
      expect(event.get("response")).to eql(404)
    end
  end

  describe 'against an unsecured elasticsearch', integration: true do
    it_behaves_like 'an elasticsearch index plugin'
  end

  describe 'against a secured elasticsearch', secure_integration: true do

    # client_options is for an out-of-band helper
    let(:client_options) { { :ca_file => ca_file, :user => user, :password => password } }

    let(:config) { super().merge('user' => user, 'password' => password) }

    shared_examples 'secured_elasticsearch' do
      it_behaves_like 'an elasticsearch index plugin'

      context "incorrect auth credentials" do

        let(:config) do
          super().merge('user' => 'archer', 'password' => 'b0gus!')
        end

        let(:queue) { [] }

        it "fails to run the plugin" do
          expect { plugin.register }.to raise_error Elasticsearch::Transport::Transport::Errors::Unauthorized
        end
      end
    end

    context 'with ca_file' do
      let(:config) { super().merge('ssl_enabled' => true, 'ssl_certificate_authorities' => ca_file) }
      it_behaves_like 'secured_elasticsearch'
    end

    context 'with `ca_trusted_fingerprint`' do
      let(:ca_trusted_fingerprint) { File.read("spec/fixtures/test_certs/ca.der.sha256").chomp }
      let(:config) { super().merge('ssl_enabled' => true, 'ca_trusted_fingerprint' => ca_trusted_fingerprint) }

      if Gem::Version.create(LOGSTASH_VERSION) >= Gem::Version.create("8.3.0")
        it_behaves_like 'secured_elasticsearch'
      else
        it 'raises a configuration error' do
          expect { plugin }.to raise_exception(LogStash::ConfigurationError, a_string_including("ca_trusted_fingerprint"))
        end
      end
    end
  end

  context 'setting host:port', integration: true do

    let(:config) do
      super().merge "hosts" => [ESHelper.get_host_port]
    end

    it_behaves_like 'an elasticsearch index plugin'

  end

  context 'setting host:port (and ssl)', secure_integration: true do

    let(:client_options) { { :ssl_certificate_authorities => ca_file, :user => user, :password => password } }

    let(:config) do
      config = super().merge "hosts" => [ESHelper.get_host_port]
      config.merge('user' => user, 'password' => password, 'ssl_enabled' => true, 'ssl_certificate_authorities' => ca_file)
    end

    it_behaves_like 'an elasticsearch index plugin'

  end

  describe 'slice', integration: true do
    let(:config) { super().merge('slices' => 2, 'size' => 2) }
    let(:plugin) { described_class.new(config) }

    it_behaves_like 'an elasticsearch index plugin'
  end
end
