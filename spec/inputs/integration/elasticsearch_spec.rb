# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin"
require "logstash/inputs/elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Inputs::Elasticsearch, :integration => true do

  let(:config)   { { 'hosts' => [ESHelper.get_host_port],
                     'index' => 'logs',
                     'query' => '{ "query": { "match": { "message": "Not found"} }}' } }
  let(:plugin) { described_class.new(config) }
  let(:event)  { LogStash::Event.new({}) }

  before(:each) do
    @es = ESHelper.get_client
    # Delete all templates first.
    # Clean ES of data before we start.
    @es.indices.delete_template(:name => "*")
    # This can fail if there are no indexes, ignore failure.
    @es.indices.delete(:index => "*") rescue nil
    10.times do
      ESHelper.index_doc(@es, :index => 'logs', :body => { :response => 404, :message=> 'Not Found'})
    end
    @es.indices.refresh
    plugin.register
  end

  after(:each) do
    @es.indices.delete_template(:name => "*")
    @es.indices.delete(:index => "*") rescue nil
  end

  describe 'smoke test' do
    it "should retrieve json event from elasticseach" do
      queue = []
      plugin.run(queue)
      event = queue.pop
      expect(event).to be_a(LogStash::Event)
      expect(event.get("response")).to eql(404)
    end
  end
end
