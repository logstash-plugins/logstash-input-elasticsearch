# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"

describe LogStash::Inputs::Elasticsearch::Esql do
  let(:client) { instance_double(Elasticsearch::Client) }
  let(:esql_client) { double("esql-client") }
  let(:plugin) { instance_double(LogStash::Inputs::Elasticsearch, params: plugin_config) }
  let(:plugin_config) do
    {
      "query" => "FROM test-index | STATS count() BY field",
      "retries" => 3
    }
  end
  let(:esql_executor) { described_class.new(client, plugin) }

  describe "when initializes" do
    it "sets up the ESQL client with correct parameters" do
      expect(esql_executor.instance_variable_get(:@query)).to eq(plugin_config["query"])
      expect(esql_executor.instance_variable_get(:@retries)).to eq(plugin_config["retries"])
    end
  end

  describe "when faces error while retrying" do
    it "retries the given block the specified number of times" do
      attempts = 0
      result = esql_executor.retryable("Test Job") do
        attempts += 1
        raise StandardError if attempts < 3
        "success"
      end
      expect(attempts).to eq(3)
      expect(result).to eq("success")
    end

    it "returns false if the block fails all attempts" do
      result = esql_executor.retryable("Test Job") do
        raise StandardError
      end
      expect(result).to eq(false)
    end
  end

  describe "when executing chain of processes" do
    let(:output_queue) { Queue.new }
    let(:response) { { 'values' => [%w[foo bar]], 'columns' => [{ 'name' => 'id'}, { 'name' => 'val'}] } }

    before do
      allow(esql_executor).to receive(:retryable).and_yield
      allow(client).to receive_message_chain(:esql, :query).and_return(response)
      allow(plugin).to receive(:decorate_and_push_to_queue)
    end

    it "executes the ESQL query and processes the results" do
      allow(response).to receive(:headers).and_return({})
      esql_executor.do_run(output_queue)
      expect(plugin).to have_received(:decorate_and_push_to_queue).with(output_queue, {'id' => 'foo', 'val' => 'bar'})
    end

    it "logs a warning if the response contains a warning header" do
      allow(response).to receive(:headers).and_return({"warning" => "some warning"})
      expect(esql_executor.logger).to receive(:warn).with("ES|QL executor received warning", {:message => "some warning"})
      esql_executor.do_run(output_queue)
    end

    it "does not log a warning if the response does not contain a warning header" do
      allow(response).to receive(:headers).and_return({})
      expect(esql_executor.logger).not_to receive(:warn)
      esql_executor.do_run(output_queue)
    end
  end


  describe "when starts processing the response" do
    let(:output_queue) { Queue.new }
    let(:values) { [%w[foo bar]] }
    let(:columns) { [{'name' => 'id'}, {'name' => 'val'}] }

    it "processes the ESQL response and pushes events to the output queue" do
      allow(plugin).to receive(:decorate_and_push_to_queue)
      esql_executor.send(:process_response, values, columns, output_queue)
      expect(plugin).to have_received(:decorate_and_push_to_queue).with(output_queue, {'id' => 'foo', 'val' => 'bar'})
    end
  end

  describe "when maps column and values" do
    let(:columns) { [{'name' => 'id'}, {'name' => 'val'}] }
    let(:values) { %w[foo bar] }

    it "maps column names to their corresponding values" do
      result = esql_executor.send(:map_column_and_values, columns, values)
      expect(result).to eq({'id' => 'foo', 'val' => 'bar'})
    end
  end
end