# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"
require_relative "../../../spec/es_helper"

describe LogStash::Inputs::Elasticsearch, integration: true do

  SECURE_INTEGRATION = ENV['SECURE_INTEGRATION'].eql? 'true'
  ES_HOSTS = ["http#{SECURE_INTEGRATION ? 's' : nil}://#{ESHelper.get_host_port}"]

  let(:plugin) { described_class.new(config) }
  let(:es_index) { "logstash-esql-integration-#{rand(1000)}" }
  let(:test_documents) do
    [
      { "message" => "test message 1", "type" => "a", "count" => 1 },
      { "message" => "test message 2", "type" => "a", "count" => 2 },
      { "message" => "test message 3", "type" => "b", "count" => 3 },
      { "message" => "test message 4", "type" => "b", "count" => 4 },
      { "message" => "test message 5", "type" => "c", "count" => 5 }
    ]
  end
  let(:config) do
    {
      "hosts" => ES_HOSTS,
      "response_type" => "esql"
    }
  end
  let(:es_client) do
    Elasticsearch::Client.new(hosts: ES_HOSTS)
  end

  before(:all) do
    is_ls_with_esql_supported_client = Gem::Version.create(LOGSTASH_VERSION) < Gem::Version.create(LogStash::Inputs::Elasticsearch::LS_ESQL_SUPPORT_VERSION)
    skip "LS version does not have ES client which supports ES|QL" unless is_ls_with_esql_supported_client

    # Skip tests if ES version doesn't support ES||QL
    es_client = Elasticsearch::Client.new(hosts: ES_HOSTS) # need to separately create since let isn't allowed in before(:context)
    es_version_info = es_client.info["version"]
    es_gem_version = Gem::Version.create(es_version_info["number"])
    skip "ES version does not support ES|QL" if es_gem_version.nil? || es_gem_version < Gem::Version.create(LogStash::Inputs::Elasticsearch::ES_ESQL_SUPPORT_VERSION)
  end

  before(:each) do
    # Create index with test documents
    es_client.indices.create(index: es_index, body: {}) unless es_client.indices.exists?(index: es_index)

    test_documents.each do |doc|
      es_client.index(index: es_index, body: doc, refresh: true)
    end
  end

  after(:each) do
    es_client.indices.delete(index: es_index) if es_client.indices.exists?(index: es_index)
  end

  context "#run ES|QL queries" do

    before do
      stub_const("LOGSTASH_VERSION", LogStash::Inputs::Elasticsearch::LS_ESQL_SUPPORT_VERSION)
      allow_any_instance_of(LogStash::Inputs::Elasticsearch).to receive(:exit_plugin?).and_return false, true
    end

    before(:each) do
      plugin.register
    end

    shared_examples "ESQL query execution" do |expected_count|
      it "correctly retrieves documents" do
        queue = Queue.new
        plugin.run(queue)

        event_count = 0
        expected_count.times do |i|
          event = queue.pop
          expect(event).to be_a(LogStash::Event)
          event_count += 1
        end
        expect(event_count).to eq(expected_count)
      end
    end

    context "#FROM query" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | SORT count")
      end

      include_examples "ESQL query execution", 5
    end

    context "#FROM query and WHERE clause" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | WHERE type == \"a\" | SORT count")
      end

      include_examples "ESQL query execution", 2
    end

    context "#STATS aggregation" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} | STATS avg(count) BY type")
      end

      it "retrieves aggregated stats" do
        queue = Queue.new
        plugin.run(queue)
        results = []
        3.times do
          event = queue.pop
          expect(event).to be_a(LogStash::Event)
          results << event.get("avg(count)")
        end

        expected_averages = [1.5, 3.5, 5.0]
        expect(results.sort).to eq(expected_averages)
      end
    end

    context "#METADATA included" do
      let(:config) do
        super().merge("query" => "FROM #{es_index} METADATA _index, _id, _version | SORT count")
      end

      it "includes document metadata" do
        queue = Queue.new
        plugin.run(queue)

        5.times do
          event = queue.pop
          expect(event).to be_a(LogStash::Event)
          expect(event.get("_index")).not_to be_nil
          expect(event.get("_id")).not_to be_nil
          expect(event.get("_version")).not_to be_nil
        end
      end
    end

    context "#invalid ES|QL query" do
      let(:config) do
        super().merge("query" => "FROM undefined index | LIMIT 1")
      end

      it "doesn't produce events" do
        queue = Queue.new
        plugin.run(queue)
        expect(queue.empty?).to eq(true)
      end
    end
  end
end