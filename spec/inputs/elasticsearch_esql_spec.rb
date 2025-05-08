# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/elasticsearch"
require "elasticsearch"

describe LogStash::Inputs::Elasticsearch::Esql do
  let(:client) { instance_double(Elasticsearch::Client) }
  let(:esql_client) { double("esql-client") }

  let(:plugin) { instance_double(LogStash::Inputs::Elasticsearch, params: plugin_config, decorate_event: nil) }
  let(:plugin_config) do
    {
      "query" => "FROM test-index | STATS count() BY field",
      "retries" => 3
    }
  end
  let(:esql_executor) { described_class.new(client, plugin) }

  describe "#initialization" do
    it "sets up the ESQL client with correct parameters" do
      expect(esql_executor.instance_variable_get(:@query)).to eq(plugin_config["query"])
      expect(esql_executor.instance_variable_get(:@retries)).to eq(plugin_config["retries"])
      expect(esql_executor.instance_variable_get(:@target_field)).to eq(nil)
    end
  end

  describe "#execution" do
    let(:output_queue) { Queue.new }

    context "when faces error while retrying" do
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

    context "when executing chain of processes" do
      let(:response) { { 'values' => [%w[foo bar]], 'columns' => [{ 'name' => 'a.b.1.d', 'type' => 'keyword' },
                                                                  { 'name' => 'h_g.k$l.m.0', 'type' => 'keyword' }] } }

      before do
        allow(esql_executor).to receive(:retryable).and_yield
        allow(client).to receive_message_chain(:esql, :query).and_return(response)
        allow(plugin).to receive(:decorate_event)
      end

      it "executes the ESQL query and processes the results" do
        allow(response).to receive(:headers).and_return({})
        esql_executor.do_run(output_queue, plugin_config["query"])
        expect(output_queue.size).to eq(1)

        event = output_queue.pop
        expect(event.get('[a][b][1][d]')).to eq('foo')
        expect(event.get('[h_g][k$l][m][0]')).to eq('bar')
      end

      it "logs a warning if the response contains a warning header" do
        allow(response).to receive(:headers).and_return({ "warning" => "some warning" })
        expect(esql_executor.logger).to receive(:warn).with("ES|QL executor received warning", { :warning_message => "some warning" })
        esql_executor.do_run(output_queue, plugin_config["query"])
      end

      it "does not log a warning if the response does not contain a warning header" do
        allow(response).to receive(:headers).and_return({})
        expect(esql_executor.logger).not_to receive(:warn)
        esql_executor.do_run(output_queue, plugin_config["query"])
      end
    end

    describe "multiple rows in the result" do
      let(:response) { { 'values' => rows, 'columns' => [{ 'name' => 'key.1', 'type' => 'keyword' },
                                                         { 'name' => 'key.2', 'type' => 'keyword' }] } }

      before do
        allow(esql_executor).to receive(:retryable).and_yield
        allow(client).to receive_message_chain(:esql, :query).and_return(response)
        allow(plugin).to receive(:decorate_event)
        allow(response).to receive(:headers).and_return({})
      end

      context "when mapping" do
        let(:rows) { [%w[foo bar], %w[hello world]] }

        it "1:1 maps rows to events" do
          esql_executor.do_run(output_queue, plugin_config["query"])
          expect(output_queue.size).to eq(2)

          event_1 = output_queue.pop
          expect(event_1.get('[key][1]')).to eq('foo')
          expect(event_1.get('[key][2]')).to eq('bar')

          event_2 = output_queue.pop
          expect(event_2.get('[key][1]')).to eq('hello')
          expect(event_2.get('[key][2]')).to eq('world')
        end
      end

      context "when partial nil values appear" do
        let(:rows) { [[nil, "bar"], ["hello", nil]] }

        it "ignores the nil values" do
          esql_executor.do_run(output_queue, plugin_config["query"])
          expect(output_queue.size).to eq(2)

          event_1 = output_queue.pop
          expect(event_1.get('[key][1]')).to eq(nil)
          expect(event_1.get('[key][2]')).to eq('bar')

          event_2 = output_queue.pop
          expect(event_2.get('[key][1]')).to eq('hello')
          expect(event_2.get('[key][2]')).to eq(nil)
        end
      end
    end
  end

  describe "#column spec" do
    let(:valid_spec) { { 'name' => 'field.name', 'type' => 'keyword' } }
    let(:column_spec) { LogStash::Inputs::Elasticsearch::ColumnSpec.new(valid_spec) }

    context "when initializes" do
      it "sets the name and type attributes" do
        expect(column_spec.name).to eq("field.name")
        expect(column_spec.type).to eq("keyword")
      end

      it "freezes the name and type attributes" do
        expect(column_spec.name).to be_frozen
        expect(column_spec.type).to be_frozen
      end
    end

    context "when calls the field reference" do
      it "returns the correct field reference format" do
        expect(column_spec.field_reference).to eq("[field][name]")
      end
    end
  end
end if LOGSTASH_VERSION >= LogStash::Inputs::Elasticsearch::LS_ESQL_SUPPORT_VERSION