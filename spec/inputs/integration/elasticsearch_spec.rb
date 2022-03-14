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

  before(:each) do
    @es = ESHelper.get_client(client_options)
    # Delete all templates first.
    # Clean ES of data before we start.
    @es.indices.delete_template(:name => "*")
    # This can fail if there are no indexes, ignore failure.
    @es.indices.delete(:index => "*") rescue nil
    10.times do
      ESHelper.index_doc(@es, :index => 'logs', :body => { :response => 404, :message=> 'Not Found'})
    end
    @es.indices.refresh
  end

  after(:each) do
    @es.indices.delete_template(:name => "*")
    @es.indices.delete(:index => "*") rescue nil
  end

  shared_examples 'an elasticsearch index plugin' do
    before(:each) do
      plugin.register
    end

    it 'should retrieve json event from elasticsearch' do
      queue = []
      plugin.run(queue)
      event = queue.pop
      expect(event).to be_a(LogStash::Event)
      expect(event.get("response")).to eql(404)
    end
  end

  describe 'against an unsecured elasticsearch', integration: true do
    before(:each) do
      plugin.register
    end

    it_behaves_like 'an elasticsearch index plugin'
  end

  describe 'against a secured elasticsearch', secure_integration: true do

    let(:client_options) { { :ca_file => ca_file, :user => user, :password => password } }

    let(:config) { super().merge('user' => user, 'password' => password, 'ssl' => true, 'ca_file' => ca_file) }

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

  context 'setting host:port', integration: true do

    let(:config) do
      super().merge "hosts" => [ESHelper.get_host_port]
    end

    it_behaves_like 'an elasticsearch index plugin'

  end

  context 'setting host:port (and ssl)', secure_integration: true do

    let(:client_options) { { :ca_file => ca_file, :user => user, :password => password } }

    let(:config) do
      config = super().merge "hosts" => [ESHelper.get_host_port]
      config.merge('user' => user, 'password' => password, 'ssl' => true, 'ca_file' => ca_file)
    end

    it_behaves_like 'an elasticsearch index plugin'

  end

end
